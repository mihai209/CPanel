import React, { useState, useEffect, useCallback, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-overview';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function StatCard({ label, value, progress, subValue, colorClass }) {
    return (
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 shadow-sm">
            <div className="flex justify-between items-center mb-4">
                <span className="text-xs font-bold text-neutral-400 uppercase tracking-widest">{label}</span>
                <span className="text-lg font-bold text-white">{value}</span>
            </div>
            <div className="h-2 bg-neutral-800 rounded-full overflow-hidden mb-3">
                <div 
                    className={`h-full transition-all duration-500 rounded-full ${colorClass}`} 
                    style={{ width: `${Math.min(progress, 100)}%` }}
                ></div>
            </div>
            <div className="text-[10px] text-neutral-500 font-medium">
                {subValue}
            </div>
        </div>
    );
}

export function ServerOverviewPage({ pageData = data }) {
    const server = pageData.server || {};
    const [stats, setStats] = useState({ cpu: 0, memory: 0, disk: 0, status: server.status || 'unknown' });
    const wsRef = useRef(null);

    const memoryLimit = Number(server.memory) || 1;
    const diskLimit = Number(server.disk) || 1;

    // WebSocket Handling logic from overview.ejs
    useEffect(() => {
        const wsToken = pageData.wsToken;
        if (!wsToken) return;

        const protocol = window.location.protocol.replace('http', 'ws');
        const url = `${protocol}//${window.location.host}/ws/server/${server.containerId}?token=${encodeURIComponent(wsToken)}`;
        
        let reconnectTimer = null;
        let reconnectInterval = 1000;

        const connect = () => {
            const ws = new WebSocket(url);
            wsRef.current = ws;

            ws.onopen = () => {
                reconnectInterval = 1000;
            };

            ws.onmessage = (event) => {
                try {
                    const payload = JSON.parse(event.data);
                    if (payload.type === 'server_stats') {
                        setStats(prev => ({
                            ...prev,
                            cpu: Number(payload.cpu) || 0,
                            memory: Number(payload.memory) || 0,
                            disk: Number(payload.disk) || 0
                        }));
                    } else if (payload.type === 'server_status_update') {
                        setStats(prev => ({ ...prev, status: payload.status }));
                    }
                } catch (e) {}
            };

            ws.onclose = () => {
                reconnectTimer = setTimeout(() => {
                    reconnectInterval = Math.min(reconnectInterval * 1.5, 5000);
                    connect();
                }, reconnectInterval);
            };
        };

        connect();

        return () => {
            if (wsRef.current) wsRef.current.close();
            if (reconnectTimer) clearTimeout(reconnectTimer);
        };
    }, [server.containerId, pageData.wsToken]);

    const memPercent = (stats.memory / memoryLimit) * 100;
    const diskPercent = (stats.disk / diskLimit) * 100;

    const getStatusColor = (status) => {
        switch(status) {
            case 'running': return 'text-green-500 bg-green-500/10 border-green-500/20';
            case 'starting': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
            case 'stopping': return 'text-red-500 bg-red-500/10 border-red-500/20';
            default: return 'text-neutral-500 bg-neutral-800 border-neutral-700';
        }
    };

    const handleCopy = (text) => {
        navigator.clipboard.writeText(text);
        // Simple visual feedback could go here if needed
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Overview">
            <PageContentBlock title={server.name} description={server.description || 'No description provided.'}>
                
                {/* Stats Grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                    <StatCard 
                        label="Processor" 
                        value={`${stats.cpu.toFixed(1)}%`} 
                        progress={stats.cpu}
                        subValue="Live CPU Usage"
                        colorClass={stats.cpu < 60 ? 'bg-green-500' : stats.cpu < 85 ? 'bg-yellow-500' : 'bg-red-500'}
                    />
                    <StatCard 
                        label="Memory" 
                        value={`${Math.round(stats.memory)} MB`} 
                        progress={memPercent}
                        subValue={`Limit: ${memoryLimit} MB`}
                        colorClass={memPercent < 60 ? 'bg-green-500' : memPercent < 85 ? 'bg-yellow-500' : 'bg-red-500'}
                    />
                    <StatCard 
                        label="Disk" 
                        value={`${Math.round(stats.disk)} MB`} 
                        progress={diskPercent}
                        subValue={`Quota: ${diskLimit} MB`}
                        colorClass={diskPercent < 60 ? 'bg-green-500' : diskPercent < 85 ? 'bg-yellow-500' : 'bg-red-500'}
                    />
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                    {/* Left Column - Core Info */}
                    <div className="lg:col-span-8 space-y-8">
                        
                        {/* Connection Info */}
                        <div className="bg-neutral-900 border border-neutral-700 rounded-xl overflow-hidden shadow-sm">
                            <div className="bg-neutral-800/50 px-5 py-4 border-b border-neutral-700 flex justify-between items-center">
                                <h3 className="font-bold text-white flex items-center gap-2">
                                    <i className="bi bi-link-45deg"></i> Connection Detail
                                </h3>
                                <div className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border ${getStatusColor(stats.status)}`}>
                                    {stats.status}
                                </div>
                            </div>
                            <div className="p-6">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div>
                                        <label className="block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-2">Primary IP / Port</label>
                                        <div className="flex items-center gap-2">
                                            <code className="bg-neutral-800 px-3 py-2 rounded text-primary-400 font-mono text-sm flex-1">
                                                {server.allocation?.ip || '0.0.0.0'}:{server.allocation?.port || '0'}
                                            </code>
                                            <button 
                                                onClick={() => handleCopy(`${server.allocation?.ip}:${server.allocation?.port}`)}
                                                className="p-2 bg-neutral-800 hover:bg-neutral-700 rounded text-neutral-400 transition" 
                                                title="Copy"
                                            >
                                                <i className="bi bi-clipboard"></i>
                                            </button>
                                        </div>
                                    </div>
                                    <div>
                                        <label className="block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-2">Container Identifier</label>
                                        <code className="block bg-neutral-800 px-3 py-2 rounded text-neutral-300 font-mono text-sm">
                                            {server.containerId}
                                        </code>
                                    </div>
                                </div>

                                <div className="mt-6 pt-6 border-t border-neutral-800">
                                    <label className="block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-2">Startup Command</label>
                                    <pre className="w-full bg-neutral-950 border border-neutral-800 rounded p-4 text-xs font-mono text-neutral-400 overflow-x-auto">
                                        {pageData.resolvedStartup || 'No startup command defined.'}
                                    </pre>
                                </div>
                            </div>
                        </div>

                        {/* Metadata Editor */}
                        <div className="bg-neutral-900 border border-neutral-700 rounded-xl overflow-hidden shadow-sm">
                            <div className="bg-neutral-800/50 px-5 py-4 border-b border-neutral-700">
                                <h3 className="font-bold text-white flex items-center gap-2">
                                    <i className="bi bi-pencil-square"></i> General Settings
                                </h3>
                            </div>
                            <div className="p-6">
                                <form method="POST" action={`/server/${server.containerId}/overview/meta`} className="space-y-6">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <div>
                                            <label className="block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-1.5">Server Name</label>
                                            <input type="text" name="name" defaultValue={server.name} className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" />
                                        </div>
                                        <div>
                                            <label className="block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-1.5">Folder</label>
                                            <input type="text" name="folder" defaultValue={server.folder} className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" />
                                        </div>
                                    </div>
                                    <div>
                                        <label className="block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-1.5">Description</label>
                                        <textarea name="description" defaultValue={server.description} rows="2" className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" />
                                    </div>
                                    <div>
                                        <label className="block text-[10px] font-bold text-neutral-500 uppercase tracking-widest mb-1.5">Tags (comma separated)</label>
                                        <input type="text" name="tags" defaultValue={(server.tags || []).join(', ')} className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" />
                                    </div>
                                    <div className="flex justify-end pt-2">
                                        <button className="bg-primary-600 hover:bg-primary-500 text-white font-bold py-2 px-6 rounded-lg transition shadow-md text-sm">
                                            Update Information
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>

                    {/* Right Column - Sidebar Widgets */}
                    <div className="lg:col-span-4 space-y-6">
                        
                        {/* Allocation Table */}
                        <div className="bg-neutral-900 border border-neutral-700 rounded-xl overflow-hidden shadow-sm">
                            <div className="bg-neutral-800/50 px-4 py-3 border-b border-neutral-700">
                                <h4 className="text-xs font-bold text-neutral-100 uppercase tracking-wider">Network Info</h4>
                            </div>
                            <div className="p-4 space-y-4">
                                <div className="flex justify-between items-center text-sm">
                                    <span className="text-neutral-500">Node</span>
                                    <span className="text-neutral-200 font-semibold">{server.allocation?.connector?.name || 'Local'}</span>
                                </div>
                                <div className="flex justify-between items-center text-sm">
                                    <span className="text-neutral-500">Location</span>
                                    <span className="text-neutral-200 font-semibold">
                                        <i className={`bi bi-geo-alt-fill text-primary-500 me-2`}></i>
                                        {server.allocation?.connector?.location?.name || 'Central'}
                                    </span>
                                </div>
                                <div className="flex justify-between items-center text-sm pt-4 border-t border-neutral-800">
                                <div className="flex items-center gap-2">
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-widest ${
                                        typeof pageData.healthScore === 'object' 
                                            ? (pageData.healthScore.badgeClass || 'bg-neutral-800 text-neutral-400')
                                            : (pageData.healthScore >= 80 ? 'bg-green-500/10 text-green-500 border-green-500/20' : pageData.healthScore >= 50 ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' : 'bg-red-500/10 text-red-500 border-red-500/20')
                                    }`}>
                                        {typeof pageData.healthScore === 'object' ? pageData.healthScore.grade : (pageData.healthScore >= 80 ? 'Healthy' : 'Warning')}
                                    </span>
                                    <span className={`font-bold ${
                                        typeof pageData.healthScore === 'object'
                                            ? (pageData.healthScore.score >= 80 ? 'text-green-500' : pageData.healthScore.score >= 50 ? 'text-yellow-500' : 'text-red-500')
                                            : (pageData.healthScore >= 80 ? 'text-green-500' : pageData.healthScore >= 50 ? 'text-yellow-500' : 'text-red-500')
                                    }`}>
                                        {typeof pageData.healthScore === 'object' ? pageData.healthScore.score : (pageData.healthScore || 0)}%
                                    </span>
                                </div>
                                </div>
                                {pageData.serverCost && (
                                    <div className="flex justify-between items-center text-sm">
                                        <span className="text-neutral-500">Monthly Est.</span>
                                        <span className="text-primary-400 font-bold">${pageData.serverCost}</span>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Minecraft Widget */}
                        {pageData.minecraftProfileCard?.enabled && (
                            <div className="bg-neutral-900 border border-neutral-700 rounded-xl overflow-hidden shadow-sm">
                                <div className="bg-emerald-600/10 px-4 py-3 border-b border-emerald-900/20 text-emerald-400 font-bold text-xs uppercase tracking-wider flex items-center gap-2">
                                    <i className="bi bi-controller"></i> Minecraft Status
                                </div>
                                <div className="p-4">
                                    <div className="flex items-center gap-4 mb-4">
                                        <img src={`https://mc-api.net/v3/server/favicon/${pageData.minecraftProfileCard.statusAddress}`} 
                                             className="w-10 h-10 rounded shadow border border-neutral-800 bg-black" 
                                             onError={(e) => e.target.src = '/assets/rocky.png'} />
                                        <div className="flex-1 min-w-0">
                                            <div className="text-sm font-bold text-white truncate">
                                                {pageData.minecraftProfileCard.status?.motd || 'MC Server'}
                                            </div>
                                            <div className="text-[10px] text-emerald-400">
                                                {pageData.minecraftProfileCard.status?.version || 'Unknown version'}
                                            </div>
                                        </div>
                                    </div>
                                    <div className="flex justify-between items-center text-sm">
                                        <span className="text-neutral-500">Players Online</span>
                                        <span className="bg-emerald-900/30 text-emerald-400 px-2 py-0.5 rounded text-xs font-bold">
                                            {pageData.minecraftProfileCard.status?.playersOnline || 0} / {pageData.minecraftProfileCard.status?.playersMax || 0}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Owner Information (Admins only) */}
                        {pageData.user?.isAdmin && server.owner && (
                            <div className="bg-neutral-900 border border-neutral-700 rounded-xl overflow-hidden shadow-sm mb-6">
                                <div className="bg-primary-900/10 px-5 py-4 border-b border-primary-900/20">
                                    <h3 className="font-black text-primary-500 text-[10px] uppercase tracking-[0.2em] flex items-center gap-2">
                                        <i className="bi bi-person-badge"></i> Owner Information
                                    </h3>
                                </div>
                                <div className="p-5 flex items-center gap-4">
                                    <div className="w-12 h-12 rounded-full bg-neutral-800 flex items-center justify-center text-xl font-bold text-neutral-400 border border-neutral-700">
                                        {server.owner.username?.charAt(0).toUpperCase() || 'U'}
                                    </div>
                                    <div className="flex-1">
                                        <div className="text-sm font-bold text-white">{server.owner.username}</div>
                                        <div className="text-[10px] text-neutral-500 font-mono">UID: {server.ownerId}</div>
                                    </div>
                                    <a href={`/admin/users/view/${server.ownerId}`} className="px-3 py-1.5 bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-[10px] font-bold uppercase tracking-widest rounded border border-neutral-700 transition">
                                        View Profile
                                    </a>
                                </div>
                            </div>
                        )}

                        <div className="p-5 border border-dashed border-neutral-800 rounded-xl">
                            <h5 className="text-xs font-bold text-neutral-400 uppercase tracking-widest mb-3">Quick Navigation</h5>
                            <div className="grid grid-cols-2 gap-2">
                                <a href={`/server/${server.containerId}/files`} className="p-3 bg-neutral-900 hover:bg-neutral-800 border border-neutral-800 rounded-lg text-center transition group">
                                    <i className="bi bi-folder2-open block text-lg text-neutral-500 group-hover:text-primary-400 mb-1"></i>
                                    <span className="text-[10px] font-bold text-neutral-400 uppercase">Files</span>
                                </a>
                                <a href={`/server/${server.containerId}/backups`} className="p-3 bg-neutral-900 hover:bg-neutral-800 border border-neutral-800 rounded-lg text-center transition group">
                                    <i className="bi bi-safe block text-lg text-neutral-500 group-hover:text-primary-400 mb-1"></i>
                                    <span className="text-[10px] font-bold text-neutral-400 uppercase">Backups</span>
                                </a>
                            </div>
                        </div>

                    </div>
                </div>

            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerOverviewPage;

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <ServerOverviewPage pageData={data} />
        </ThemeProvider>
    );
}