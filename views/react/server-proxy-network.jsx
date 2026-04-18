import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ThemeProvider from './components/ThemeContext.jsx';
import ReactAppShell from './components/ReactAppShell';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-proxy-network';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export default function ServerProxyNetworkPage({ pageData = {} }) {
    const { 
        server = {}, 
        proxyMode = '', 
        proxySnapshot: initialSnapshot = {}, 
        proxyGroupedBackends: initialGroups = [], 
        proxyUngroupedBackends: initialUngrouped = [], 
        proxyLinkableServers = [] 
    } = pageData;

    const [snapshot, setSnapshot] = useState(initialSnapshot);
    const [loading, setLoading] = useState(false);
    const [status, setStatus] = useState({ 
        type: pageData.error ? 'error' : (pageData.success ? 'success' : 'idle'), 
        message: pageData.error || pageData.success || '' 
    });

    const summary = snapshot.summary || {};
    const backends = Array.isArray(snapshot.backends) ? snapshot.backends : [];
    const groups = Array.isArray(snapshot.groups) ? snapshot.groups : [];
    
    // Polling for status updates
    useEffect(() => {
        const interval = setInterval(async () => {
            try {
                const response = await fetch(`/server/${server.containerId}/minecraft/proxy/status`, {
                    headers: { 'Accept': 'application/json' },
                    cache: 'no-store'
                });
                if (!response.ok) return;
                const payload = await response.json();
                if (payload && payload.success && payload.snapshot) {
                    setSnapshot(payload.snapshot);
                }
            } catch (err) {
                // Background fail
            }
        }, 12000);
        return () => clearInterval(interval);
    }, [server.containerId]);

    const handleAction = async (url, method = 'POST', body = null) => {
        setLoading(true);
        setStatus({ type: 'idle', message: '' });
        try {
            const options = { method };
            if (body) {
                options.headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
                options.body = new URLSearchParams(body);
            }

            const res = await fetch(url, options);
            if (res.redirected) {
                window.location.href = res.url;
                return;
            }

            const data = await res.json();
            if (!res.ok || data.error) throw new Error(data.error || 'Action failed');
            
            setStatus({ type: 'success', message: data.message || 'Action completed successfully.' });
            
            // Refresh snapshot after action
            if (data.snapshot) setSnapshot(data.snapshot);
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
        } finally {
            setLoading(false);
        }
    };

    const Section = ({ title, icon, children }) => (
        <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 overflow-hidden shadow-sm flex flex-col">
            <div className="px-6 py-4 bg-neutral-900/30 border-b border-neutral-800 flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <i className={`bi ${icon} text-primary-400`}></i>
                    <h3 className="text-sm font-black text-neutral-500 uppercase tracking-widest">{title}</h3>
                </div>
            </div>
            <div className="p-6">
                {children}
            </div>
        </div>
    );

    const StatCard = ({ label, value, colorClass = 'text-neutral-200' }) => (
        <div className="bg-neutral-950/50 border border-neutral-800 rounded-xl p-4 flex flex-col gap-1 shadow-sm">
            <span className="text-[10px] font-black text-neutral-600 uppercase tracking-widest">{label}</span>
            <span className={`text-2xl font-black ${colorClass}`}>{value}</span>
        </div>
    );

    return (
        <ReactAppShell pageData={pageData} subtitle="Proxy Network">
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

                {/* ── Dashboard Stats ───────────────────────────────── */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <StatCard label="Proxy Players" value={summary.proxyPlayersOnline || 0} colorClass="text-blue-400" />
                    <StatCard label="Backend Players" value={summary.backendPlayersOnline || 0} colorClass="text-primary-400" />
                    <StatCard label="Online Backends" value={summary.backendOnline || 0} colorClass="text-green-400" />
                    <StatCard label="Offline Backends" value={summary.backendOffline || 0} colorClass="text-red-400" />
                </div>

                {/* ── Proxy Endpoint Info ───────────────────────────── */}
                <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 p-6 flex flex-wrap gap-6 items-center justify-between shadow-sm">
                    <div className="flex items-center gap-4">
                        <div className="w-12 h-12 rounded-2xl bg-primary-500/10 flex items-center justify-center border border-primary-500/20">
                            <i className="bi bi-hdd-network-fill text-primary-400 text-xl"></i>
                        </div>
                        <div>
                            <span className="text-[10px] font-black text-neutral-600 uppercase tracking-widest block mb-0.5">Proxy Endpoint</span>
                            <code className="text-lg font-mono text-neutral-200">{snapshot.proxyAddress || 'unknown'}</code>
                            <div className="flex items-center gap-2 mt-1">
                                <span className={`w-2 h-2 rounded-full ${snapshot.proxyStatus?.online ? 'bg-green-500' : 'bg-red-500'}`}></span>
                                <span className="text-xs text-neutral-500 font-bold uppercase tracking-tight">
                                    {snapshot.proxyStatus?.online ? 'Online' : `Offline ${snapshot.proxyStatus?.error || ''}`}
                                </span>
                            </div>
                        </div>
                    </div>
                    <div className="flex gap-2">
                        <button 
                            onClick={() => handleAction(`/server/${server.containerId}/minecraft/proxy/sync-config`)}
                            disabled={loading}
                            className="px-6 py-2 rounded-xl bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-black uppercase tracking-widest transition-all border border-neutral-700 shadow-lg"
                        >
                            <i className="bi bi-arrow-repeat me-2"></i>Sync Config
                        </button>
                    </div>
                </div>

                <div className="grid lg:grid-cols-3 gap-6">
                    {/* ── Backends Table ────────────────────────────────── */}
                    <div className="lg:col-span-2 space-y-6">
                        <Section title="Network Backends" icon="bi-grid-fill">
                            <div className="space-y-6">
                                {/* Add Backend Form */}
                                <form 
                                    onSubmit={(e) => {
                                        e.preventDefault();
                                        const fd = new FormData(e.target);
                                        handleAction(`/server/${server.containerId}/minecraft/proxy/backends/add`, 'POST', {
                                            linkedContainerId: fd.get('linkedContainerId'),
                                            groupId: fd.get('groupId')
                                        });
                                    }}
                                    className="p-4 bg-neutral-950/50 border border-neutral-800 rounded-xl grid md:grid-cols-3 gap-4 items-end"
                                >
                                    <div className="md:col-span-2">
                                        <label className="text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1 mb-2 block">Quick Add From Panel</label>
                                        <select name="linkedContainerId" required className="w-full bg-neutral-900 border border-neutral-800 rounded-xl px-4 py-2.5 text-xs text-neutral-300 focus:outline-none focus:border-primary-500/50">
                                            <option value="">Select compatible server...</option>
                                            {proxyLinkableServers.map(s => (
                                                <option key={s.containerId} value={s.containerId}>
                                                    {s.name} ({s.allocation?.alias || s.allocation?.ip}:{s.allocation?.port})
                                                </option>
                                            ))}
                                        </select>
                                    </div>
                                    <div>
                                        <label className="text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1 mb-2 block">Assigned Group</label>
                                        <select name="groupId" className="w-full bg-neutral-900 border border-neutral-800 rounded-xl px-4 py-2.5 text-xs text-neutral-300 focus:outline-none focus:border-primary-500/50">
                                            <option value="">Ungrouped</option>
                                            {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
                                        </select>
                                    </div>
                                    <div className="md:col-span-3 flex justify-end pt-2">
                                        <button type="submit" disabled={loading || proxyLinkableServers.length === 0} className="px-8 py-2.5 rounded-xl bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-800 text-white text-xs font-black uppercase tracking-widest transition-all">
                                            Add Backend
                                        </button>
                                    </div>
                                </form>

                                {/* Backends List */}
                                <div className="overflow-x-auto">
                                    <table className="w-full text-left border-collapse">
                                        <thead>
                                            <tr className="border-b border-neutral-800">
                                                <th className="px-4 py-3 text-[10px] font-black text-neutral-600 uppercase tracking-widest">Name/Address</th>
                                                <th className="px-4 py-3 text-[10px] font-black text-neutral-600 uppercase tracking-widest text-center">Group</th>
                                                <th className="px-4 py-3 text-[10px] font-black text-neutral-600 uppercase tracking-widest text-center">Status</th>
                                                <th className="px-4 py-3 text-[10px] font-black text-neutral-600 uppercase tracking-widest text-right">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-neutral-800/50">
                                            {backends.length === 0 ? (
                                                <tr>
                                                    <td colSpan="4" className="px-4 py-12 text-center text-sm text-neutral-600 italic">No backends configured yet.</td>
                                                </tr>
                                            ) : (
                                                backends.map((backend) => (
                                                    <tr key={backend.id} className="hover:bg-white/[0.02] transition-colors group">
                                                        <td className="px-4 py-4">
                                                            <div className="font-bold text-neutral-200 text-sm">{backend.name}</div>
                                                            <code className="text-[10px] font-mono text-neutral-500">{backend.address}</code>
                                                        </td>
                                                        <td className="px-4 py-4">
                                                            <div className="flex justify-center">
                                                                <select 
                                                                    value={backend.groupId || ''} 
                                                                    onChange={(e) => handleAction(`/server/${server.containerId}/minecraft/proxy/backends/${backend.id}/group`, 'POST', { groupId: e.target.value })}
                                                                    className="bg-neutral-950/50 border border-neutral-800 rounded-lg px-2 py-1 text-[11px] text-neutral-400 focus:outline-none"
                                                                >
                                                                    <option value="">-</option>
                                                                    {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
                                                                </select>
                                                            </div>
                                                        </td>
                                                        <td className="px-4 py-4 text-center">
                                                            <div className="flex flex-col items-center gap-1">
                                                                <span className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-widest ${backend.status?.online ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}`}>
                                                                    {backend.status?.online ? 'Online' : 'Offline'}
                                                                </span>
                                                                <span className="text-[10px] font-bold text-neutral-600">{backend.status?.playersOnline || 0} / {backend.status?.playersMax || 0}</span>
                                                            </div>
                                                        </td>
                                                        <td className="px-4 py-4">
                                                            <div className="flex justify-end gap-1.5 opacity-40 group-hover:opacity-100 transition-opacity">
                                                                {backend.linkedContainerId && (
                                                                    <>
                                                                        <button onClick={() => handleAction(`/server/${server.containerId}/minecraft/proxy/backends/${backend.id}/power`, 'POST', { action: 'restart' })} className="w-8 h-8 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-yellow-500 flex items-center justify-center hover:bg-yellow-500/20 transition-all shadow-sm" title="Smart Restart"><i className="bi bi-arrow-repeat"></i></button>
                                                                        <button onClick={() => handleAction(`/server/${server.containerId}/minecraft/proxy/restart-sequence`, 'POST', { backendId: backend.id })} className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center hover:bg-blue-500/20 transition-all shadow-sm" title="Smart Flow Restart"><i className="bi bi-diagram-2"></i></button>
                                                                    </>
                                                                )}
                                                                <button 
                                                                    onClick={() => { if(confirm('Delete backend?')) handleAction(`/server/${server.containerId}/minecraft/proxy/backends/${backend.id}/delete`, 'POST'); }}
                                                                    className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 flex items-center justify-center hover:bg-red-500/20 transition-all shadow-sm"
                                                                >
                                                                    <i className="bi bi-trash"></i>
                                                                </button>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </Section>
                    </div>

                    {/* ── Groups & Automation ────────────────────────────── */}
                    <div className="space-y-6">
                        <Section title="Groups" icon="bi-collection-play-fill">
                            <form 
                                onSubmit={(e) => {
                                    e.preventDefault();
                                    const name = e.target.name.value;
                                    handleAction(`/server/${server.containerId}/minecraft/proxy/groups/add`, 'POST', { name });
                                    e.target.reset();
                                }}
                                className="flex gap-2 mb-6"
                            >
                                <input name="name" required placeholder="New group..." className="flex-1 bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2 text-xs text-neutral-300 focus:outline-none focus:border-primary-500/50" />
                                <button type="submit" className="w-10 h-10 rounded-xl bg-primary-600 hover:bg-primary-500 text-white flex items-center justify-center transition-all"><i className="bi bi-plus-lg"></i></button>
                            </form>

                            <div className="space-y-3">
                                {groups.length === 0 ? (
                                    <div className="text-center py-6 text-xs text-neutral-600 font-bold uppercase tracking-tight">No groups defined.</div>
                                ) : (
                                    groups.map(group => (
                                        <div key={group.id} className="p-4 bg-neutral-950/50 border border-neutral-800 rounded-2xl space-y-4 shadow-sm group/card">
                                            <div className="flex justify-between items-center">
                                                <div className="font-black text-sm text-neutral-200 uppercase tracking-widest">{group.name}</div>
                                                <button 
                                                    onClick={() => { if(confirm('Delete group?')) handleAction(`/server/${server.containerId}/minecraft/proxy/groups/${group.id}/delete`, 'POST'); }}
                                                    className="w-7 h-7 rounded-lg text-neutral-600 hover:text-red-400 hover:bg-red-400/10 flex items-center justify-center transition-all opacity-0 group-hover/card:opacity-100"
                                                >
                                                    <i className="bi bi-trash text-xs"></i>
                                                </button>
                                            </div>
                                            <div className="text-[10px] font-black text-neutral-600 uppercase tracking-widest">
                                                Backends: {backends.filter(b => b.groupId === group.id).length}
                                            </div>
                                            <div className="grid grid-cols-2 gap-2">
                                                <button onClick={() => handleAction(`/server/${server.containerId}/minecraft/proxy/groups/${group.id}/power`, 'POST', { action: 'start' })} className="py-2 rounded-lg bg-green-500/10 border border-green-500/20 text-green-400 text-[10px] font-black uppercase tracking-widest hover:bg-green-500/20 transition-all">Start All</button>
                                                <button onClick={() => handleAction(`/server/${server.containerId}/minecraft/proxy/groups/${group.id}/power`, 'POST', { action: 'restart' })} className="py-2 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 text-[10px] font-black uppercase tracking-widest hover:bg-yellow-500/20 transition-all">Reboot All</button>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </Section>

                        <Section title="Smart Actions" icon="bi-magic">
                            <div className="space-y-4">
                                <div className="p-4 bg-blue-500/5 rounded-xl border border-blue-500/10">
                                    <h4 className="text-[10px] font-black text-blue-400 uppercase tracking-widest mb-1">Smart Restart Sequence</h4>
                                    <p className="text-[11px] text-neutral-500 leading-relaxed mb-4">Reboot a backend server, wait for it to become healthy, then automatically refresh the proxy configuration.</p>
                                    
                                    <form 
                                        onSubmit={(e) => {
                                            e.preventDefault();
                                            handleAction(`/server/${server.containerId}/minecraft/proxy/restart-sequence`, 'POST', { backendId: e.target.backendId.value });
                                        }}
                                        className="space-y-2"
                                    >
                                        <select name="backendId" required className="w-full bg-neutral-900 border border-neutral-800 rounded-xl px-4 py-2.5 text-xs text-neutral-300 focus:outline-none">
                                            <option value="">Select target backend...</option>
                                            {backends.filter(b => b.linkedContainerId).map(b => (
                                                <option key={b.id} value={b.id}>{b.name} ({b.linkedContainerId})</option>
                                            ))}
                                        </select>
                                        <button type="submit" disabled={loading} className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-[10px] font-black uppercase tracking-widest transition-all shadow-lg shadow-blue-950/20">
                                            Run Sequence
                                        </button>
                                    </form>
                                </div>
                            </div>
                        </Section>
                    </div>
                </div>
            </div>
        </ReactAppShell>
    );
}

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <BrowserRouter>
                <ServerProxyNetworkPage pageData={data} />
            </BrowserRouter>
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
