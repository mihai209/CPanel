import React, { useState } from 'react';
import ReactAppShell from './components/ReactAppShell';

export default function ServerPerformancePage({ pageData = {} }) {
    const { 
        server = {}, 
        performanceRows = [], 
        performanceStats = { pluginsCount: 0, modsCount: 0, totalSizeMb: 0 },
        performanceReportUrl: initialReportUrl = '',
        canRunCommands = false 
    } = pageData;

    const [loading, setLoading] = useState(false);
    const [reportUrl, setReportUrl] = useState(initialReportUrl);
    const [status, setStatus] = useState({ 
        type: pageData.error ? 'error' : (pageData.success ? 'success' : 'idle'), 
        message: pageData.error || pageData.success || '' 
    });

    const handleRunTimings = async () => {
        if (!canRunCommands) return;
        setLoading(true);
        setStatus({ type: 'idle', message: '' });

        try {
            const res = await fetch(`/server/${server.containerId}/performance/run-timings`, { method: 'POST' });
            const data = await res.json();
            if (!res.ok || !data.success) throw new Error(data.error || 'Failed to dispatch timings report.');
            
            setStatus({ type: 'success', message: 'Timings report command sent. Wait for the URL in console, then paste it below.' });
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
        } finally {
            setLoading(false);
        }
    };

    const handleSaveReportUrl = async (e) => {
        e.preventDefault();
        setLoading(true);
        setStatus({ type: 'idle', message: '' });

        try {
            const res = await fetch(`/server/${server.containerId}/performance/report`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ reportUrl })
            });

            if (res.redirected) {
                window.location.href = res.url;
                return;
            }

            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Failed to save report URL');
            
            setStatus({ type: 'success', message: 'Performance report link updated successfully.' });
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
        } finally {
            setLoading(false);
        }
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Performance Insights">
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

                {/* ── Resource Summary Header ────────────────────────── */}
                <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 p-6 flex flex-wrap items-center justify-between gap-6 shadow-sm">
                    <div className="space-y-4 flex-1 min-w-[300px]">
                        <div>
                            <h2 className="text-lg font-bold text-white flex items-center gap-2">
                                <i className="bi bi-cpu text-primary-400"></i>
                                Resource Audit
                            </h2>
                            <p className="text-xs text-neutral-500 mt-1 uppercase tracking-wider font-semibold">
                                Size-based estimate for plugin & mod overhead
                            </p>
                        </div>
                        <div className="flex flex-wrap gap-3">
                            <div className="px-4 py-2 rounded-xl bg-primary-500/5 border border-primary-500/20 flex items-center gap-2.5">
                                <i className="bi bi-plug text-primary-400"></i>
                                <span className="text-xs font-bold text-neutral-300">{performanceStats.pluginsCount} <span className="text-[10px] text-neutral-500 font-normal ml-0.5 uppercase tracking-tighter">Plugins</span></span>
                            </div>
                            <div className="px-4 py-2 rounded-xl bg-purple-500/5 border border-purple-500/20 flex items-center gap-2.5">
                                <i className="bi bi-puzzle text-purple-400"></i>
                                <span className="text-xs font-bold text-neutral-300">{performanceStats.modsCount} <span className="text-[10px] text-neutral-500 font-normal ml-0.5 uppercase tracking-tighter">Mods</span></span>
                            </div>
                            <div className="px-4 py-2 rounded-xl bg-blue-500/5 border border-blue-500/20 flex items-center gap-2.5">
                                <i className="bi bi-hdd text-blue-400"></i>
                                <span className="text-xs font-bold text-neutral-300">{performanceStats.totalSizeMb} <span className="text-[10px] text-neutral-500 font-normal ml-0.5 uppercase tracking-tighter">MB Total</span></span>
                            </div>
                        </div>
                    </div>

                    <div className="flex gap-2">
                        {canRunCommands && (
                            <button
                                onClick={handleRunTimings}
                                disabled={loading}
                                className="px-5 py-2.5 rounded-xl bg-neutral-800 hover:bg-neutral-700 text-white text-xs font-bold transition-all flex items-center gap-2"
                            >
                                <i className="bi bi-play-circle-fill"></i>
                                Run Timings Report
                            </button>
                        )}
                    </div>
                </div>

                <div className="grid lg:grid-cols-3 gap-6">
                    {/* ── Left: Inventory Table ───────────────────────────── */}
                    <div className="lg:col-span-2 space-y-6">
                        <div className="bg-neutral-900/50 rounded-2xl border border-neutral-800 shadow-sm overflow-hidden">
                            <div className="p-6 border-b border-neutral-800">
                                <h3 className="text-sm font-black text-neutral-500 uppercase tracking-widest">Storage Impact (Top 20)</h3>
                            </div>
                            {performanceRows.length === 0 ? (
                                <div className="p-12 text-center">
                                    <i className="bi bi-search text-4xl text-neutral-800 mb-3 block"></i>
                                    <p className="text-neutral-500 text-sm font-medium">No plugins or mods detected.</p>
                                    <p className="text-[10px] text-neutral-600 uppercase tracking-widest mt-1">Check if the server is installed correctly</p>
                                </div>
                            ) : (
                                <div className="overflow-x-auto no-scrollbar pb-2">
                                    <table className="w-full text-left border-separate border-spacing-y-1 px-4">
                                        <thead>
                                            <tr className="text-[10px] font-black text-neutral-600 uppercase tracking-widest">
                                                <th className="py-4 pl-4">Asset</th>
                                                <th className="py-4 px-4">Impact</th>
                                                <th className="py-4 pr-4">Location</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {performanceRows.map((row, i) => (
                                                <tr key={i} className="group hover:bg-neutral-800/10 transition-colors">
                                                    <td className="py-3 pl-4 rounded-l-xl">
                                                        <div className="flex items-center gap-3">
                                                            <span className={`w-8 h-8 rounded-lg flex items-center justify-center text-[10px] font-black uppercase ${
                                                                row.kind === 'plugin' ? 'bg-primary-500/10 text-primary-500' : 'bg-purple-500/10 text-purple-500'
                                                            }`}>
                                                                {row.kind === 'plugin' ? 'P' : 'M'}
                                                            </span>
                                                            <span className="font-bold text-sm text-neutral-300">{row.name}</span>
                                                        </div>
                                                    </td>
                                                    <td className="py-3 px-4">
                                                        <div className="flex items-center gap-2">
                                                            <div className="flex-1 max-w-[60px] h-1 rounded-full bg-neutral-800 overflow-hidden">
                                                                <div 
                                                                    className={`h-full ${row.sizeMb > 20 ? 'bg-red-500' : row.sizeMb > 5 ? 'bg-orange-500' : 'bg-primary-500'}`} 
                                                                    style={{ width: `${Math.min(100, (row.sizeMb / performanceStats.totalSizeMb) * 400)}%` }}
                                                                ></div>
                                                            </div>
                                                            <span className="text-[11px] font-bold text-neutral-400">{row.sizeMb} MB</span>
                                                        </div>
                                                    </td>
                                                    <td className="py-3 pr-4 rounded-r-xl">
                                                        <code className="text-[10px] text-neutral-600 bg-neutral-950/5 px-2 py-1 rounded truncate block max-w-[200px]" title={row.path}>{row.path}</code>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* ── Right: Report Management ────────────────────────── */}
                    <div className="space-y-6">
                        <div className="bg-neutral-900/80 backdrop-blur-md rounded-2xl border border-neutral-800 p-6 shadow-xl space-y-6">
                            <div>
                                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                    <i className="bi bi-link-45deg text-blue-400"></i>
                                    External Profiler
                                </h3>
                                <p className="text-xs text-neutral-500 mt-1 leading-relaxed">
                                    Track deep performance reports from Spark, Timings, or other profilers here.
                                </p>
                            </div>

                            {reportUrl && (
                                <a 
                                    href={reportUrl} 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                    className="block p-4 rounded-xl bg-blue-500/10 border border-blue-500/20 hover:bg-blue-500/20 transition-all text-center group"
                                >
                                    <div className="text-[10px] font-black text-blue-400 uppercase tracking-widest mb-1">Active Report</div>
                                    <div className="text-xs font-bold text-blue-200 truncate group-hover:underline">{reportUrl}</div>
                                    <i className="bi bi-box-arrow-up-right text-[10px] mt-2 block opacity-50 group-hover:opacity-100"></i>
                                </a>
                            )}

                            <form onSubmit={handleSaveReportUrl} className="space-y-4">
                                <div className="space-y-2">
                                    <label className="text-[10px] font-black text-neutral-500 uppercase tracking-widest px-1">Sync Report URL</label>
                                    <input 
                                        type="url"
                                        required
                                        value={reportUrl}
                                        onChange={e => setReportUrl(e.target.value)}
                                        placeholder="Paste timings or spark URL"
                                        className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-3 text-sm text-neutral-300 focus:outline-none focus:border-primary-500"
                                    />
                                </div>
                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full py-3.5 rounded-xl bg-primary-600 hover:bg-primary-500 text-white font-bold transition-all shadow-lg shadow-primary-900/20 text-sm"
                                >
                                    {loading ? <i className="bi bi-arrow-repeat animate-spin"></i> : 'Update Report Link'}
                                </button>
                            </form>
                            
                            <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-800 space-y-3">
                                <div className="flex items-center gap-2 text-[11px] font-bold text-neutral-400">
                                    <i className="bi bi-patch-question"></i>
                                    How to profile?
                                </div>
                                <ol className="text-[10px] text-neutral-600 space-y-2 list-decimal ml-4 uppercase tracking-tight font-black">
                                    <li>Type <code className="text-primary-400">timings on</code> in console</li>
                                    <li>Wait 10 minutes of gameplay</li>
                                    <li>Type <code className="text-primary-400">timings paste</code></li>
                                    <li>Copy and save the link here</li>
                                </ol>
                            </div>
                        </div>

                        {/* Tip Card */}
                        <div className="bg-primary-500/5 rounded-2xl border border-primary-500/10 p-6 space-y-3">
                            <h4 className="text-sm font-bold text-primary-400 flex items-center gap-2 lowercase italic">
                                <i className="bi bi-lightning"></i>
                                Optimization Tip
                            </h4>
                            <p className="text-xs text-neutral-500 leading-relaxed">
                                Assets over <span className="text-neutral-300 font-bold">50MB</span> often indicate large resource packs or heavy dependencies that contribute to slower startup times.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </ReactAppShell>
    );
}
