import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ThemeProvider from './components/ThemeContext.jsx';
import ReactAppShell from './components/ReactAppShell';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-mounts';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export default function ServerMountsPage({ pageData = {} }) {
    const { server = {}, assignedMounts = [], availableMounts = [], canManageMounts = false } = pageData;
    const [loading, setLoading] = useState(false);
    const [status, setStatus] = useState({ type: pageData.error ? 'error' : (pageData.success ? 'success' : 'idle'), message: pageData.error || pageData.success || '' });

    const [selectedMount, setSelectedMount] = useState('');
    const [readOnly, setReadOnly] = useState(false);

    const handleAttach = async (e) => {
        e.preventDefault();
        if (!selectedMount || !canManageMounts) return;

        setLoading(true);
        setStatus({ type: 'idle', message: '' });

        try {
            const res = await fetch(`/server/${server.containerId}/mounts/attach`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ mountId: selectedMount, readOnly: readOnly ? '1' : '0' })
            });

            if (res.redirected) {
                window.location.href = res.url;
                return;
            }

            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Failed to attach mount');
            window.location.reload();
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
            setLoading(false);
        }
    };

    const handleDetach = async (mountId) => {
        if (!canManageMounts || !window.confirm('Are you sure you want to detach this mount?')) return;

        setLoading(true);
        setStatus({ type: 'idle', message: '' });

        try {
            const res = await fetch(`/server/${server.containerId}/mounts/detach`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ mountId })
            });

            if (res.redirected) {
                window.location.href = res.url;
                return;
            }

            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Failed to detach mount');
            window.location.reload();
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
            setLoading(false);
        }
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Mount Management">
            <div className="max-w-7xl mx-auto space-y-6">
                {/* ── Status Messages ─────────────────────────────────── */}
                {status.message && (
                    <div className={`p-4 rounded-xl border flex items-center gap-3 animate-in fade-in slide-in-from-top-2 duration-300 ${
                        status.type === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-400' : 
                        status.type === 'success' ? 'bg-green-500/10 border-green-500/20 text-green-400' : 
                        'bg-blue-500/10 border-blue-500/20 text-blue-400'
                    }`}>
                        <i className={`bi ${status.type === 'error' ? 'bi-exclamation-triangle-fill' : status.type === 'success' ? 'bi-check-circle-fill' : 'bi-info-circle-fill'}`}></i>
                        <span className="text-sm font-medium">{status.message}</span>
                        <button onClick={() => setStatus({ type: 'idle', message: '' })} className="ml-auto opacity-50 hover:opacity-100 transition-opacity">
                            <i className="bi bi-x-lg"></i>
                        </button>
                    </div>
                )}

                <div className="grid lg:grid-cols-3 gap-6">
                    {/* ── Left: Assigned Mounts ──────────────────────────── */}
                    <div className="lg:col-span-2 space-y-6">
                        <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 p-6 shadow-sm overflow-hidden">
                            <div className="flex items-center justify-between mb-6">
                                <div>
                                    <h2 className="text-lg font-bold text-white flex items-center gap-2">
                                        <i className="bi bi-hdd-stack text-primary-400"></i>
                                        Assigned Mounts
                                    </h2>
                                    <p className="text-xs text-neutral-500 mt-1 uppercase tracking-wider font-semibold">
                                        Mounts apply on next reinstall or container rebuild
                                    </p>
                                </div>
                                <span className="px-2.5 py-1 rounded-full bg-neutral-800 text-[10px] font-black uppercase tracking-widest text-neutral-400">
                                    {assignedMounts.length} Mounts
                                </span>
                            </div>

                            {assignedMounts.length === 0 ? (
                                <div className="text-center py-12 bg-neutral-950/30 rounded-xl border border-dashed border-neutral-800">
                                    <i className="bi bi-folder-x text-4xl text-neutral-700 mb-3 block"></i>
                                    <p className="text-neutral-500 text-sm font-medium">No mounts assigned yet.</p>
                                </div>
                            ) : (
                                <div className="overflow-x-auto no-scrollbar">
                                    <table className="w-full text-left border-separate border-spacing-y-2">
                                        <thead>
                                            <tr className="text-[10px] font-black text-neutral-500 uppercase tracking-widest px-4">
                                                <th className="pb-3 pl-4">Name</th>
                                                <th className="pb-3 px-4">Source → Target</th>
                                                <th className="pb-3 px-4">Mode</th>
                                                <th className="pb-3 px-4">Connector</th>
                                                <th className="pb-3 pr-4 text-right">Action</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {assignedMounts.map((mount) => (
                                                <tr key={mount.id} className="group bg-neutral-900/30 hover:bg-neutral-800/20 transition-all">
                                                    <td className="py-4 pl-4 rounded-l-xl">
                                                        <div className="font-bold text-neutral-200 text-sm">{mount.name}</div>
                                                        <div className="text-[10px] text-neutral-600 truncate max-w-[150px]">{mount.id}</div>
                                                    </td>
                                                    <td className="py-4 px-4 font-mono text-[11px]">
                                                        <div className="text-neutral-500 truncate max-w-[120px]" title={mount.sourcePath}>{mount.sourcePath}</div>
                                                        <div className="text-blue-400 truncate max-w-[120px]" title={mount.targetPath}>{mount.targetPath}</div>
                                                    </td>
                                                    <td className="py-4 px-4">
                                                        {mount.readOnly ? (
                                                            <span className="px-2 py-0.5 rounded bg-neutral-800 text-neutral-500 text-[9px] font-black uppercase tracking-tighter">Read-Only</span>
                                                        ) : (
                                                            <span className="px-2 py-0.5 rounded bg-green-500/10 text-green-500 text-[9px] font-black uppercase tracking-tighter">Writable</span>
                                                        )}
                                                    </td>
                                                    <td className="py-4 px-4">
                                                        <span className="text-[11px] font-bold text-neutral-400">{mount.connectorName || 'Any'}</span>
                                                    </td>
                                                    <td className="py-4 pr-4 text-right rounded-r-xl">
                                                        {canManageMounts && (
                                                            <button
                                                                onClick={() => handleDetach(mount.id)}
                                                                disabled={loading}
                                                                className="px-3 py-1.5 rounded-lg bg-red-500/10 text-red-500 hover:bg-red-500 hover:text-white transition-all text-[11px] font-bold"
                                                            >
                                                                Detach
                                                            </button>
                                                        )}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>

                        {/* ── Help / Info ─────────────────────────────────── */}
                        <div className="bg-blue-500/5 rounded-2xl border border-blue-500/10 p-6">
                            <h3 className="text-sm font-bold text-blue-400 mb-3 flex items-center gap-2">
                                <i className="bi bi-info-circle"></i>
                                What are Mounts?
                            </h3>
                            <div className="grid md:grid-cols-2 gap-4 text-xs text-neutral-400 leading-relaxed">
                                <div className="space-y-2">
                                    <p><span className="text-neutral-200 font-bold">Shared Storage:</span> Mounts attach a host directory into your container, enabling cross-server data sharing.</p>
                                    <p><span className="text-neutral-200 font-bold">Use Cases:</span> Ideal for shared Minecraft libraries, plugin configurations, or global assets.</p>
                                </div>
                                <div className="space-y-2">
                                    <p><span className="text-neutral-200 font-bold">Persistence:</span> Changes to writable mounts persist on the host system, surviving server reinstalls.</p>
                                    <p><span className="text-neutral-200 font-bold">Lifecycle:</span> New mount assignments are applied only when a container is rebuilt or reinstalled.</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* ── Right: Available Mounts ─────────────────────────── */}
                    <div className="space-y-6">
                        <div className="bg-neutral-900/80 backdrop-blur-md rounded-2xl border border-neutral-800 p-6 shadow-xl sticky top-6">
                            <h2 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                                <i className="bi bi-plus-circle-fill text-green-500"></i>
                                Attach Mount
                            </h2>

                            {availableMounts.length === 0 ? (
                                <div className="p-4 rounded-xl bg-neutral-950/50 border border-neutral-800 text-center space-y-2">
                                    <p className="text-neutral-600 text-sm">No available mounts found.</p>
                                    <p className="text-[10px] text-neutral-700 uppercase tracking-widest font-black">
                                        Check Admin Panel → Mounts
                                    </p>
                                </div>
                            ) : (
                                <form onSubmit={handleAttach} className="space-y-5">
                                    <div className="space-y-2">
                                        <label className="text-[10px] font-black text-neutral-500 uppercase tracking-widest px-1">Select Mount</label>
                                        <select
                                            value={selectedMount}
                                            onChange={(e) => setSelectedMount(e.target.value)}
                                            className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-3 text-sm text-neutral-200 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/20"
                                            disabled={loading}
                                        >
                                            <option value="">Choose a mount...</option>
                                            {availableMounts.map((mount) => (
                                                <option key={mount.id} value={mount.id}>
                                                    {mount.name} ({mount.targetPath})
                                                </option>
                                            ))}
                                        </select>
                                    </div>

                                    <div className="flex items-center justify-between p-3 rounded-xl bg-neutral-950 border border-neutral-800 transition-all hover:border-neutral-700">
                                        <div className="flex flex-col">
                                            <span className="text-[11px] font-bold text-neutral-300">Read-Only Mode</span>
                                            <span className="text-[9px] text-neutral-600 uppercase tracking-tighter">Prevents write access</span>
                                        </div>
                                        <button
                                            type="button"
                                            onClick={() => setReadOnly(!readOnly)}
                                            className={`relative w-10 h-5 rounded-full transition-colors duration-200 ${readOnly ? 'bg-primary-500' : 'bg-neutral-800'}`}
                                            disabled={loading}
                                        >
                                            <div className={`absolute top-1 left-1 w-3 h-3 bg-white rounded-full transition-transform duration-200 ${readOnly ? 'translate-x-5' : ''}`}></div>
                                        </button>
                                    </div>

                                    <button
                                        type="submit"
                                        disabled={loading || !selectedMount || !canManageMounts}
                                        className="w-full py-3.5 rounded-xl bg-primary-600 hover:bg-primary-500 text-white font-bold transition-all shadow-lg shadow-primary-900/20 disabled:opacity-50 disabled:cursor-not-allowed text-sm"
                                    >
                                        {loading ? <span className="flex items-center justify-center gap-2"><i className="bi bi-arrow-repeat animate-spin"></i> Processing...</span> : 'Attach to Server'}
                                    </button>
                                </form>
                            )}

                            {!canManageMounts && (
                                <div className="mt-4 p-3 rounded-xl bg-red-500/10 border border-red-500/10 text-red-500 text-[10px] font-bold text-center uppercase tracking-wider leading-relaxed">
                                    <i className="bi bi-shield-lock-fill mr-1"></i>
                                    You don't have permission to manage mounts.
                                </div>
                            )}
                        </div>
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
                <ServerMountsPage pageData={data} />
            </BrowserRouter>
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
