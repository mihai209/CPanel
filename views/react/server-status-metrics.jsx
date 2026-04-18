import React, { useState, useEffect, useRef } from 'react';
import ReactAppShell from './components/ReactAppShell';

const TPS_COLOR = '#22c55e';
const MSPT_COLOR = '#3b82f6';
const LAG_COLOR = '#f59e0b';

export default function ServerStatusMetricsPage({ pageData = {} }) {
    const { server = {}, isMinecraft = false } = pageData;
    const [tickSamples, setTickSamples] = useState([]);
    const [crashLoop, setCrashLoop] = useState(null);
    const [worlds, setWorlds] = useState([]);
    const [worldsMeta, setWorldsMeta] = useState('Loading...');
    const [packPlayers, setPackPlayers] = useState([]);
    const [packMeta, setPackMeta] = useState('Waiting for updates...');
    const [loading, setLoading] = useState({ ticks: false, worlds: false, pack: false });

    const tpsCanvasRef = useRef(null);
    const msptCanvasRef = useRef(null);

    // ── Data Fetching ────────────────────────────────────────────────
    const loadTickMetrics = async () => {
        setLoading(prev => ({ ...prev, ticks: true }));
        try {
            const res = await fetch(`/server/${server.containerId}/metrics/ticks`);
            const data = await res.json();
            if (data.success) {
                setTickSamples(data.samples || []);
                setCrashLoop(data.crashLoop || null);
            }
        } catch (err) { console.error('Ticks error:', err); }
        setLoading(prev => ({ ...prev, ticks: false }));
    };

    const loadWorldMetrics = async () => {
        setLoading(prev => ({ ...prev, worlds: true }));
        setWorldsMeta('Refreshing...');
        try {
            const res = await fetch(`/server/${server.containerId}/metrics/worlds`);
            const data = await res.json();
            if (data.success) {
                setWorlds(data.worlds || []);
                setWorldsMeta(`Updated: ${new Date(data.generatedAt).toLocaleString()}${data.cached ? ' (cached)' : ''}`);
            } else {
                setWorldsMeta(data.error || 'Failed to load');
            }
        } catch (err) { setWorldsMeta('Error loading metrics'); }
        setLoading(prev => ({ ...prev, worlds: false }));
    };

    const loadResourcePackStatus = async () => {
        setLoading(prev => ({ ...prev, pack: true }));
        try {
            const res = await fetch(`/server/${server.containerId}/metrics/resource-pack`);
            const data = await res.json();
            if (data.success) {
                setPackPlayers(data.players || []);
                setPackMeta(data.updatedAt ? `Last update: ${new Date(data.updatedAt).toLocaleString()}` : 'No events yet');
            }
        } catch (err) { setPackMeta('Error loading status'); }
        setLoading(prev => ({ ...prev, pack: false }));
    };

    useEffect(() => {
        loadTickMetrics();
        loadWorldMetrics();
        loadResourcePackStatus();

        const tickInt = setInterval(loadTickMetrics, 15000);
        const packInt = setInterval(loadResourcePackStatus, 12000);
        return () => { clearInterval(tickInt); clearInterval(packInt); };
    }, []);

    // ── Chart Rendering ─────────────────────────────────────────────
    useEffect(() => {
        const renderCharts = () => {
            const draw = (canvas, pts, keyOrKeys, colors, maxVal) => {
                if (!canvas) return;
                const ctx = canvas.getContext('2d');
                const dpr = window.devicePixelRatio || 1;
                const rect = canvas.getBoundingClientRect();
                canvas.width = rect.width * dpr;
                canvas.height = rect.height * dpr;
                ctx.scale(dpr, dpr);
                const w = rect.width;
                const h = rect.height;

                ctx.fillStyle = '#0c0d10';
                ctx.fillRect(0, 0, w, h);

                // Grids
                ctx.strokeStyle = '#2d2d35';
                ctx.lineWidth = 0.5;
                for (let i = 0; i <= 4; i++) {
                    const y = 10 + (h - 20) * (i / 4);
                    ctx.beginPath();
                    ctx.moveTo(10, y);
                    ctx.lineTo(w - 10, y);
                    ctx.stroke();
                }

                const data = pts.slice(-120);
                if (data.length < 2) return;

                const keys = Array.isArray(keyOrKeys) ? keyOrKeys : [keyOrKeys];
                const lineColors = Array.isArray(colors) ? colors : [colors];

                keys.forEach((key, kIdx) => {
                    ctx.beginPath();
                    data.forEach((p, i) => {
                        const x = 10 + (w - 20) * (i / (data.length - 1));
                        const val = Math.max(0, Math.min(maxVal, Number(p[key]) || 0));
                        const y = 10 + (h - 20) * (1 - val / maxVal);
                        if (i === 0) ctx.moveTo(x, y);
                        else ctx.lineTo(x, y);
                    });
                    ctx.strokeStyle = lineColors[kIdx];
                    ctx.lineWidth = 2;
                    ctx.stroke();
                });
            };

            draw(tpsCanvasRef.current, tickSamples, 'tps1m', TPS_COLOR, 20);
            const mMax = Math.max(50, ...tickSamples.map(s => Math.max(Number(s.mspt1m) || 0, Number(s.tickLag) || 0)));
            draw(msptCanvasRef.current, tickSamples, ['mspt1m', 'tickLag'], [MSPT_COLOR, LAG_COLOR], mMax);
        };

        renderCharts();
        window.addEventListener('resize', renderCharts);
        return () => window.removeEventListener('resize', renderCharts);
    }, [tickSamples]);

    const lastTick = tickSamples[tickSamples.length - 1] || {};

    return (
        <ReactAppShell pageData={pageData} subtitle="Status & Metrics">
            <div className="max-w-7xl mx-auto space-y-6">
                {/* ── Tick Performance Section ────────────────────────── */}
                <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 p-6 shadow-sm overflow-hidden">
                    <div className="flex flex-wrap items-center justify-between gap-4 mb-8">
                        <div>
                            <h2 className="text-lg font-bold text-white flex items-center gap-2">
                                <i className="bi bi-speedometer text-primary-400"></i>
                                Tick Engine Performance
                            </h2>
                            <p className="text-[10px] text-neutral-500 uppercase tracking-widest font-black mt-1">Real-time Minecraft Internal Metrics</p>
                        </div>
                        <div className="flex gap-4">
                            <div className="flex items-center gap-2 text-[11px] font-bold">
                                <span className="w-2 h-2 rounded-full" style={{ background: TPS_COLOR }}></span>
                                <span className="text-neutral-400">TPS (1m):</span>
                                <span className="text-white font-mono">{lastTick.tps1m?.toFixed(2) || '--'}</span>
                            </div>
                            <div className="flex items-center gap-2 text-[11px] font-bold">
                                <span className="w-2 h-2 rounded-full" style={{ background: MSPT_COLOR }}></span>
                                <span className="text-neutral-400">MSPT (1m):</span>
                                <span className="text-white font-mono">{lastTick.mspt1m?.toFixed(2) || '--'} ms</span>
                            </div>
                            <div className="flex items-center gap-2 text-[11px] font-bold">
                                <span className="w-2 h-2 rounded-full" style={{ background: LAG_COLOR }}></span>
                                <span className="text-neutral-400">Tick Lag:</span>
                                <span className="text-white font-mono">{Number(lastTick.tickLag || 0).toFixed(2)} ms</span>
                            </div>
                        </div>
                    </div>

                    <div className="grid lg:grid-cols-2 gap-6">
                        <div className="space-y-3">
                            <div className="text-[10px] font-black text-neutral-600 uppercase tracking-tighter px-1">Ticks Per Second (Target: 20)</div>
                            <canvas ref={tpsCanvasRef} className="w-full h-[220px] rounded-xl border border-neutral-800/50" />
                        </div>
                        <div className="space-y-3">
                            <div className="text-[10px] font-black text-neutral-600 uppercase tracking-tighter px-1">MSPT & Lag Bursts</div>
                            <canvas ref={msptCanvasRef} className="w-full h-[220px] rounded-xl border border-neutral-800/50" />
                        </div>
                    </div>

                    <div className="mt-8 pt-6 border-t border-neutral-800 flex flex-wrap items-center justify-between gap-6">
                        <div className="flex items-center gap-3">
                            <div className="p-3 rounded-xl bg-red-500/5 border border-red-500/10 flex items-center gap-3">
                                <i className="bi bi-shield-exclamation text-red-500"></i>
                                <div className="leading-tight">
                                    <div className="text-[9px] text-neutral-600 font-bold uppercase tracking-widest">Crash Loop Guard</div>
                                    <div className="text-xs font-bold text-neutral-300">
                                        {crashLoop?.active ? `Cooldown active until ${new Date(crashLoop.cooldownUntil).toLocaleTimeString()}` : `Clear (${crashLoop?.count || 0} recent crashes)`}
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="text-[10px] text-neutral-600 font-bold flex items-center gap-2">
                            <i className="bi bi-clock-history"></i>
                            LAST DATA POINT: {lastTick.ts ? new Date(lastTick.ts).toLocaleTimeString() : 'WAITING...'}
                        </div>
                    </div>
                </div>

                <div className="grid lg:grid-cols-2 gap-6">
                    {/* ── World Metrics ─────────────────────────────────── */}
                    <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 p-6 shadow-sm">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="font-bold text-white flex items-center gap-2 uppercase tracking-wide">
                                <i className="bi bi-globe text-blue-400"></i>
                                World Statistics
                            </h3>
                            <button 
                                onClick={loadWorldMetrics} 
                                disabled={loading.worlds}
                                className="p-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-400 transition-colors"
                            >
                                <i className={`bi bi-arrow-repeat ${loading.worlds ? 'animate-spin' : ''}`}></i>
                            </button>
                        </div>
                        <div className="text-[10px] text-neutral-600 font-bold mb-4 uppercase tracking-tighter">
                            {worldsMeta}
                        </div>
                        <div className="overflow-x-auto no-scrollbar">
                            <table className="w-full text-left border-separate border-spacing-y-1">
                                <thead>
                                    <tr className="text-[10px] text-neutral-600 font-black uppercase tracking-widest">
                                        <th className="pb-3 pl-2">World</th>
                                        <th className="pb-3 px-2">Size</th>
                                        <th className="pb-3 px-2">Regions</th>
                                        <th className="pb-3 px-2">Chunks</th>
                                        <th className="pb-3 pr-2 text-right">Players</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {worlds.length === 0 ? (
                                        <tr><td colSpan="5" className="py-8 text-center text-xs text-neutral-600 italic">No world data available.</td></tr>
                                    ) : (
                                        worlds.map((w, i) => (
                                            <tr key={i} className="bg-neutral-950/20 group hover:bg-primary-500/5 transition-colors">
                                                <td className="py-3 pl-2 rounded-l-lg text-sm font-bold text-neutral-300">{w.name}</td>
                                                <td className="py-3 px-2 text-xs text-neutral-500 font-mono">{Number(w.sizeMb || 0).toFixed(1)} MB</td>
                                                <td className="py-3 px-2 text-xs text-neutral-500">{w.regionFiles}</td>
                                                <td className="py-3 px-2 text-xs text-neutral-500">{w.chunkEstimate}</td>
                                                <td className="py-3 pr-2 text-right rounded-r-lg text-xs font-black text-primary-500">{w.knownPlayers}</td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    {/* ── Resource Pack ─────────────────────────────────── */}
                    <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 p-6 shadow-sm">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="font-bold text-white flex items-center gap-2 uppercase tracking-wide">
                                <i className="bi bi-box-seam text-purple-400"></i>
                                Resource Pack Status
                            </h3>
                            <button 
                                onClick={loadResourcePackStatus} 
                                disabled={loading.pack}
                                className="p-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-400 transition-colors"
                            >
                                <i className={`bi bi-arrow-repeat ${loading.pack ? 'animate-spin' : ''}`}></i>
                            </button>
                        </div>
                        <div className="text-[10px] text-neutral-600 font-bold mb-4 uppercase tracking-tighter">
                            {packMeta}
                        </div>
                        <div className="overflow-x-auto no-scrollbar">
                            <table className="w-full text-left border-separate border-spacing-y-1">
                                <thead>
                                    <tr className="text-[10px] text-neutral-600 font-black uppercase tracking-widest">
                                        <th className="pb-3 pl-2">Player</th>
                                        <th className="pb-3 px-2">Status</th>
                                        <th className="pb-3 pr-2 text-right">Timestamp</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {packPlayers.length === 0 ? (
                                        <tr><td colSpan="3" className="py-8 text-center text-xs text-neutral-600 italic">No resource pack events yet.</td></tr>
                                    ) : (
                                        packPlayers.map((p, i) => (
                                            <tr key={i} className="bg-neutral-950/20 group hover:bg-purple-500/5 transition-colors">
                                                <td className="py-3 pl-2 rounded-l-lg text-sm font-bold text-neutral-300">{p.name}</td>
                                                <td className="py-3 px-2">
                                                    <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider ${
                                                        p.status === 'SUCCESSFULLY_LOADED' ? 'bg-green-500/10 text-green-500' : 
                                                        p.status === 'DECLINED' ? 'bg-red-500/10 text-red-500' : 
                                                        'bg-neutral-800 text-neutral-500'
                                                    }`}>
                                                        {p.status.replace(/_/g, ' ')}
                                                    </span>
                                                </td>
                                                <td className="py-3 pr-2 text-right rounded-r-lg text-xs font-mono text-neutral-600">
                                                    {p.updatedAt ? new Date(p.updatedAt).toLocaleTimeString() : 'N/A'}
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                        <div className="mt-8 p-4 rounded-xl bg-neutral-950/50 border border-neutral-800/50 text-[10px] text-neutral-500 leading-relaxed italic">
                            Resource pack monitoring requires the plugin or a compatible core to emit status packets via the connector. Decline events often indicate user side configuration issues.
                        </div>
                    </div>
                </div>
            </div>
        </ReactAppShell>
    );
}
