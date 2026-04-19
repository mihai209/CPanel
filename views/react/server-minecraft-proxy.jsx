import React, { useState, useEffect, useMemo } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-minecraft-proxy';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function StatCard({ label, value, colorClass, icon }) {
    return (
        <div className="bg-neutral-900 border border-neutral-800 rounded-3xl p-6 shadow-xl shadow-black/20">
            <div className="flex items-center gap-4 mb-3">
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center text-lg ${colorClass}`}>
                    <i className={`bi ${icon}`}></i>
                </div>
                <span className="text-[10px] font-black text-neutral-500 uppercase tracking-widest">{label}</span>
            </div>
            <div className="text-3xl font-black text-white px-1">{value}</div>
        </div>
    );
}

function BackendRow({ backend, groups, serverId, onAction }) {
    const status = backend.status || {};
    
    return (
        <tr className="group hover:bg-neutral-800/10 transition-colors">
            <td className="py-6 pl-2">
                <div className="font-mono text-sm text-white font-bold">{backend.name}</div>
                <div className="font-mono text-[10px] text-neutral-600 uppercase tracking-tighter">{backend.address}</div>
            </td>
            <td>
                <select 
                    value={backend.groupId || ''} 
                    onChange={(e) => onAction('group', backend.id, e.target.value)}
                    className="bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2 text-[10px] font-black text-neutral-400 uppercase tracking-widest focus:outline-none focus:border-primary-500/50"
                >
                    <option value="">No Group</option>
                    {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
                </select>
            </td>
            <td>
                <div className="text-sm font-black text-neutral-300">
                    {status.playersOnline || 0} / {status.playersMax || 0}
                </div>
            </td>
            <td>
                {status.online ? (
                    <span className="px-3 py-1 bg-emerald-600/10 text-emerald-500 text-[9px] font-black uppercase rounded-lg border border-emerald-900/30">Online</span>
                ) : (
                    <span className="px-3 py-1 bg-rose-600/10 text-rose-500 text-[9px] font-black uppercase rounded-lg border border-rose-900/30">Offline</span>
                )}
            </td>
            <td>
                {backend.linkedServer ? (
                    <div className="flex flex-col">
                        <span className="text-xs font-black text-primary-400 uppercase tracking-tight">{backend.linkedServer.name}</span>
                        <span className="text-[9px] text-neutral-600 font-bold uppercase tracking-widest">{backend.linkedServer.status}</span>
                    </div>
                ) : <span className="text-neutral-700">---</span>}
            </td>
            <td className="pr-2">
                <div className="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    {backend.linkedContainerId && (
                        <button 
                            onClick={() => onAction('power', backend.id, 'restart')}
                            className="p-2 bg-amber-600/10 text-amber-500 rounded-lg hover:bg-amber-600 hover:text-white transition"
                            title="Restart Server"
                        >
                            <i className="bi bi-arrow-repeat"></i>
                        </button>
                    )}
                    <button 
                        onClick={() => onAction('delete', backend.id)}
                        className="p-2 bg-rose-600/10 text-rose-500 rounded-lg hover:bg-rose-600 hover:text-white transition"
                        title="Remove from Proxy"
                    >
                        <i className="bi bi-trash3"></i>
                    </button>
                </div>
            </td>
        </tr>
    );
}

export function ServerMinecraftProxyPage({ pageData = data }) {
    const server = pageData.server || {};
    const [snapshot, setSnapshot] = useState(pageData.proxySnapshot || {});
    const [linkableServers, setLinkableServers] = useState(pageData.proxyLinkableServers || []);
    
    const [loading, setLoading] = useState(false);
    const [proxyMode, setProxyMode] = useState(pageData.proxyMode || '');
    const [setupMode, setSetupMode] = useState('bungeecord');
    const [newBackendServer, setNewBackendServer] = useState('');
    const [newBackendGroup, setNewBackendGroup] = useState('');
    const [newGroupName, setNewGroupName] = useState('');

    const summary = snapshot.summary || {};
    const backends = useMemo(() => snapshot.backends || [], [snapshot]);
    const groups = useMemo(() => snapshot.groups || [], [snapshot]);

    useEffect(() => {
        const poll = () => {
            fetch(`/server/${server.containerId}/minecraft/proxy/status`)
                .then(res => res.json())
                .then(payload => {
                    if (payload.success) setSnapshot(payload.snapshot || {});
                })
                .catch(console.error);
        };
        const interval = setInterval(poll, 10000);
        return () => clearInterval(interval);
    }, [server.containerId]);

    const handleAction = (type, id, val) => {
        const post = (url, body) => {
            setLoading(true);
            return fetch(`/server/${server.containerId}/minecraft/proxy${url}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            })
            .then(res => {
                if (res.redirected) {
                    window.location.href = res.url;
                    return;
                }
                return res.json();
            });
        };

        if (type === 'configure') {
            post('/configure', { mode: id })
                .then(payload => {
                    setLoading(false);
                    if (payload.success) {
                        setProxyMode(payload.mode);
                        window.location.reload(); // Refresh to get all data
                    } else {
                        alert('Failed to configure proxy: ' + (payload.error || 'Unknown error'));
                    }
                })
                .catch(err => {
                    setLoading(false);
                    alert('Error: ' + err.message);
                });
            return;
        }

        if (type === 'add-backend') {
            post('/backends/add', { linkedContainerId: newBackendServer, groupId: newBackendGroup })
                .then(() => setLoading(false)).catch(() => setLoading(false));
        } else if (type === 'delete') {
            if (confirm('Remove this backend from proxy?')) {
                post(`/backends/${id}/delete`, {})
                    .then(() => setLoading(false)).catch(() => setLoading(false));
            }
        } else if (type === 'group') {
            post(`/backends/${id}/group`, { groupId: val })
                .then(() => setLoading(false)).catch(() => setLoading(false));
        } else if (type === 'power') {
            post(`/backends/${id}/power`, { action: val })
                .then(() => setLoading(false)).catch(() => setLoading(false));
        } else if (type === 'sync') {
            post('/sync-config', {})
                .then(() => setLoading(false)).catch(() => setLoading(false));
        } else if (type === 'add-group') {
            post('/groups/add', { name: newGroupName })
                .then(() => {
                    setLoading(false);
                    setNewGroupName('');
                }).catch(() => setLoading(false));
        } else if (type === 'delete-group') {
            if (confirm('Delete this group?')) {
                post(`/groups/${id}/delete`, {})
                    .then(() => setLoading(false)).catch(() => setLoading(false));
            }
        }
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Proxy Network">
            <PageContentBlock 
                title="Proxy Network" 
                description={proxyMode ? `Dynamic management of the ${proxyMode} mesh for ${server.name}.` : `Initialize a scalable Minecraft mesh network.`}
                eyebrow="Network Orchestration"
            >
                {!proxyMode ? (
                    <div className="max-w-4xl mx-auto py-12">
                        <div className="bg-neutral-900 border border-neutral-800 rounded-[3.5rem] p-12 shadow-2xl shadow-black/40 text-center">
                            <div className="w-24 h-24 rounded-[2rem] bg-primary-600/10 flex items-center justify-center text-5xl text-primary-500 mx-auto mb-10 shadow-2xl shadow-primary-900/10">
                                <i className="bi bi-diagram-3"></i>
                            </div>
                            <h2 className="text-3xl font-black text-white uppercase tracking-tight mb-4">Initialize Proxy Mesh</h2>
                            <p className="text-sm text-neutral-500 font-medium leading-relaxed max-w-lg mx-auto mb-12 uppercase tracking-widest opacity-60">
                                Connect multiple servers under a single IP using a high-performance proxy gateway. Select your preferred engine to begin.
                            </p>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-12">
                                <button 
                                    onClick={() => setSetupMode('bungeecord')}
                                    className={`p-8 rounded-[2.5rem] border-2 transition-all text-left ${setupMode === 'bungeecord' ? 'bg-primary-600/5 border-primary-500/50 shadow-2xl shadow-primary-900/10' : 'bg-neutral-950/50 border-neutral-800 hover:border-neutral-700'}`}
                                >
                                    <div className={`w-12 h-12 rounded-2xl flex items-center justify-center text-xl mb-6 ${setupMode === 'bungeecord' ? 'bg-primary-500 text-white' : 'bg-neutral-900 text-neutral-500'}`}>
                                        <i className="bi bi-box"></i>
                                    </div>
                                    <h4 className="text-lg font-black text-white uppercase mb-1">BungeeCord</h4>
                                    <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest">Industry standard proxy engine</p>
                                </button>
                                <button 
                                    onClick={() => setSetupMode('velocity')}
                                    className={`p-8 rounded-[2.5rem] border-2 transition-all text-left ${setupMode === 'velocity' ? 'bg-sky-600/5 border-sky-500/50 shadow-2xl shadow-sky-900/10' : 'bg-neutral-950/50 border-neutral-800 hover:border-neutral-700'}`}
                                >
                                    <div className={`w-12 h-12 rounded-2xl flex items-center justify-center text-xl mb-6 ${setupMode === 'velocity' ? 'bg-sky-500 text-white' : 'bg-neutral-900 text-neutral-500'}`}>
                                        <i className="bi bi-lightning-charge"></i>
                                    </div>
                                    <h4 className="text-lg font-black text-white uppercase mb-1">Velocity</h4>
                                    <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest">High performance modern proxy</p>
                                </button>
                            </div>

                            <button 
                                onClick={() => handleAction('configure', setupMode)}
                                disabled={loading}
                                className="w-full py-6 bg-primary-600 hover:bg-primary-500 text-white text-xs font-black uppercase tracking-[0.3em] rounded-3xl shadow-2xl shadow-primary-900/20 transition active:scale-95 disabled:opacity-50"
                            >
                                {loading ? 'Initializing Mesh...' : 'Begin Provisioning'}
                            </button>
                        </div>
                    </div>
                ) : (
                    <>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                            <StatCard label="Mesh Players" value={summary.proxyPlayersOnline || 0} colorClass="bg-primary-600/10 text-primary-500" icon="bi-people" />
                            <StatCard label="Server Load" value={summary.backendPlayersOnline || 0} colorClass="bg-sky-600/10 text-sky-500" icon="bi-controller" />
                            <StatCard label="Live Nodes" value={summary.backendOnline || 0} colorClass="bg-emerald-600/10 text-emerald-500" icon="bi-check-circle" />
                            <StatCard label="Offline" value={summary.backendOffline || 0} colorClass="bg-rose-600/10 text-rose-500" icon="bi-exclamation-triangle" />
                        </div>

                        <div className="flex flex-wrap gap-4 mb-12 bg-neutral-900 border border-neutral-800 rounded-[2.5rem] p-8 shadow-2xl shadow-black/40">
                            <div className="flex-1 min-w-[300px]">
                                <div className="flex items-center gap-4 mb-2">
                                    <span className="text-[10px] font-black text-neutral-500 uppercase tracking-widest">Global Endpoint</span>
                                    {snapshot.proxyStatus?.online ? (
                                        <span className="text-[9px] font-black text-emerald-500 uppercase flex items-center gap-1"><i className="bi bi-circle-fill text-[6px]"></i> Online</span>
                                    ) : (
                                        <span className="text-[9px] font-black text-rose-500 uppercase flex items-center gap-1"><i className="bi bi-circle-fill text-[6px]"></i> Gateway Error</span>
                                    )}
                                </div>
                                <div className="font-mono text-xl text-white font-bold">{snapshot.proxyAddress || 'Mesh Initializing...'}</div>
                            </div>
                            <div className="flex gap-4 items-center">
                                <button 
                                    onClick={() => handleAction('sync')}
                                    className="px-8 py-3 bg-neutral-800 hover:bg-neutral-700 text-white text-[10px] font-black uppercase tracking-widest rounded-2xl transition shadow-xl active:scale-95 border border-neutral-700"
                                >
                                    Sync Config
                                </button>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 xl:grid-cols-12 gap-12">
                            <div className="xl:col-span-8">
                                <div className="mb-12">
                                    <div className="flex items-center justify-between mb-8">
                                        <h3 className="text-sm font-black text-white uppercase tracking-[0.2em] flex items-center gap-3">
                                            <span className="w-8 h-8 rounded-xl bg-neutral-900 border border-neutral-800 flex items-center justify-center text-[10px] shadow-2xl">1</span>
                                            Provision Backend
                                        </h3>
                                    </div>
                                    <div className="bg-neutral-900/40 border border-neutral-800 rounded-[3rem] p-10 flex flex-col md:flex-row items-end gap-6 shadow-2xl shadow-black/20">
                                        <div className="flex-1 w-full">
                                            <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 ml-1">Connect Panel Server</label>
                                            <select 
                                                value={newBackendServer} 
                                                onChange={(e) => setNewBackendServer(e.target.value)}
                                                className="w-full bg-neutral-950 border border-neutral-800 rounded-2xl px-5 py-4 text-xs font-black text-white focus:outline-none focus:border-primary-500/50 transition-all uppercase tracking-widest"
                                            >
                                                <option value="">Select Target...</option>
                                                {linkableServers.map(s => (
                                                    <option key={s.containerId} value={s.containerId}>{s.name} ({s.allocation?.ip}:{s.allocation?.port})</option>
                                                ))}
                                            </select>
                                        </div>
                                        <div className="flex-1 w-full">
                                            <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 ml-1">Network Group</label>
                                            <select 
                                                value={newBackendGroup} 
                                                onChange={(e) => setNewBackendGroup(e.target.value)}
                                                className="w-full bg-neutral-950 border border-neutral-800 rounded-2xl px-5 py-4 text-xs font-black text-white focus:outline-none focus:border-primary-500/50 transition-all uppercase tracking-widest"
                                            >
                                                <option value="">No Group</option>
                                                {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
                                            </select>
                                        </div>
                                        <button 
                                            onClick={() => handleAction('add-backend')}
                                            disabled={!newBackendServer || loading}
                                            className="px-10 py-5 bg-primary-600 hover:bg-primary-500 text-white text-[11px] font-black uppercase tracking-[0.25em] rounded-2xl transition shadow-2xl shadow-primary-900/20 active:scale-95"
                                        >
                                            Attach
                                        </button>
                                    </div>
                                </div>

                                <div>
                                    <h3 className="text-sm font-black text-white uppercase tracking-[0.2em] mb-8 flex items-center gap-3">
                                        <span className="w-8 h-8 rounded-xl bg-neutral-900 border border-neutral-800 flex items-center justify-center text-[10px] shadow-2xl">2</span>
                                        Network Topography
                                    </h3>
                                    <div className="bg-neutral-900 border border-neutral-800 rounded-[3rem] overflow-hidden shadow-2xl shadow-black/40">
                                        <div className="overflow-x-auto">
                                            <table className="w-full text-left">
                                                <thead>
                                                    <tr className="border-b border-neutral-800 bg-neutral-950/20">
                                                        <th className="py-5 px-6 text-[10px] font-black text-neutral-500 uppercase tracking-widest">Backend Identity</th>
                                                        <th className="py-5 px-2 text-[10px] font-black text-neutral-500 uppercase tracking-widest">Routing Group</th>
                                                        <th className="py-5 px-2 text-[10px] font-black text-neutral-500 uppercase tracking-widest">Population</th>
                                                        <th className="py-5 px-2 text-[10px] font-black text-neutral-500 uppercase tracking-widest">Status</th>
                                                        <th className="py-5 px-2 text-[10px] font-black text-neutral-500 uppercase tracking-widest">Linked Control</th>
                                                        <th className="py-5 px-6 text-[10px] font-black text-neutral-500 uppercase tracking-widest text-right">Actions</th>
                                                    </tr>
                                                </thead>
                                                <tbody className="divide-y divide-neutral-800/50">
                                                    {backends.length > 0 ? (
                                                        backends.map(b => (
                                                            <BackendRow key={b.id} backend={b} groups={groups} serverId={server.containerId} onAction={handleAction} />
                                                        ))
                                                    ) : (
                                                        <tr>
                                                            <td colSpan="6" className="py-20 text-center opacity-30">
                                                                <i className="bi bi-diagram-2 text-6xl mb-4 block"></i>
                                                                <span className="text-sm font-black uppercase tracking-[0.3em]">Isolated Proxy - No Backends</span>
                                                            </td>
                                                        </tr>
                                                    )}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="xl:col-span-4 flex flex-col gap-12">
                                <div>
                                    <h3 className="text-sm font-black text-white uppercase tracking-[0.2em] mb-8 flex items-center gap-3">
                                        Clusters
                                    </h3>
                                    <div className="bg-neutral-900 border border-neutral-800 rounded-[3rem] p-8 shadow-2xl shadow-black/40">
                                        <div className="flex gap-2 mb-8">
                                            <input 
                                                type="text" 
                                                placeholder="Group Name..." 
                                                value={newGroupName}
                                                onChange={(e) => setNewGroupName(e.target.value)}
                                                className="flex-1 bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-3 text-xs font-bold text-white focus:outline-none focus:border-primary-500/50 transition-all uppercase tracking-widest"
                                            />
                                            <button 
                                                onClick={() => handleAction('add-group')}
                                                className="px-6 bg-emerald-600/10 text-emerald-500 rounded-xl hover:bg-emerald-600 hover:text-white transition active:scale-95"
                                            >
                                                <i className="bi bi-plus-lg"></i>
                                            </button>
                                        </div>

                                        <div className="space-y-4">
                                            {groups.length > 0 ? (
                                                groups.map(g => (
                                                    <div key={g.id} className="bg-neutral-950 border border-neutral-800 rounded-2xl p-5 group flex items-center justify-between gap-4">
                                                        <div>
                                                            <h5 className="text-sm font-black text-white uppercase tracking-tight mb-1">{g.name}</h5>
                                                            <span className="text-[10px] font-bold text-neutral-600 uppercase tracking-widest">
                                                                {backends.filter(b => b.groupId === g.id).length} Nodes Connected
                                                            </span>
                                                        </div>
                                                        <button 
                                                            onClick={() => handleAction('delete-group', g.id)}
                                                            className="p-2 text-rose-600 opacity-0 group-hover:opacity-100 transition"
                                                        >
                                                            <i className="bi bi-trash3"></i>
                                                        </button>
                                                    </div>
                                                ))
                                            ) : (
                                                <div className="text-center py-8 opacity-20 text-[10px] font-black uppercase tracking-widest">No Network Groups</div>
                                            )}
                                        </div>
                                    </div>
                                </div>

                                <div className="bg-primary-600/5 border border-primary-600/10 rounded-[3rem] p-10 mt-auto">
                                    <i className="bi bi-lightning-charge text-primary-500 text-3xl mb-6 block"></i>
                                    <h4 className="text-lg font-black text-white uppercase tracking-tight mb-3">Live Provisioning</h4>
                                    <p className="text-[11px] text-neutral-500 font-bold uppercase leading-relaxed tracking-widest mb-8">
                                        Use Sync Config to instantly broadcast changes to the proxy engine without a full restart.
                                    </p>
                                    <button 
                                        onClick={() => handleAction('sync')}
                                        className="w-full py-4 bg-white text-neutral-950 text-[10px] font-black uppercase tracking-[0.2em] rounded-xl shadow-2xl transition hover:bg-primary-50 active:scale-95"
                                    >
                                        Re-broadcast Config
                                    </button>
                                </div>
                            </div>
                        </div>
                    </>
                )}
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerMinecraftProxyPage;

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <BrowserRouter>
            <ServerMinecraftProxyPage pageData={data} />
        </BrowserRouter>
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
