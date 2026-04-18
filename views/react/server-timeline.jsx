import React, { useState, useEffect, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-timeline';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

const MAX_POINTS = 180;

export function ServerTimelinePage({ pageData = data }) {
    const server = pageData.server || {};
    const canvasRef = useRef(null);
    const [history, setHistory] = useState([]);
    const [stats, setStats] = useState({ cpu: 0, memory: 0, disk: 0, lastUpdate: null });
    
    const memoryLimit = Math.max(1, Number(server.memory) || 1);
    const diskLimit = Math.max(1, Number(server.disk) || 1);

    // Initialize history from bridge data
    useEffect(() => {
        if (pageData.samples && Array.isArray(pageData.samples)) {
            const initial = pageData.samples.map(row => ({
                ts: row.collectedAt ? new Date(row.collectedAt).getTime() : Date.now(),
                cpu: Math.max(0, parseFloat(row.cpuPercent) || 0),
                mem: Math.max(0, parseFloat(row.memoryMb) || 0),
                disk: Math.max(0, parseFloat(row.diskMb) || 0)
            })).slice(-MAX_POINTS);
            setHistory(initial);
            if (initial.length > 0) {
                const last = initial[initial.length - 1];
                setStats({ cpu: last.cpu, memory: last.mem, disk: last.disk, lastUpdate: new Date(last.ts) });
            }
        }
    }, [pageData.samples]);

    // WebSocket logic
    useEffect(() => {
        const wsToken = pageData.wsToken;
        if (!wsToken) return;

        const protocol = window.location.protocol.replace('http', 'ws');
        const url = `${protocol}//${window.location.host}/ws/server/${server.containerId}?token=${encodeURIComponent(wsToken)}`;
        
        let ws = null;
        const connect = () => {
            ws = new WebSocket(url);
            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (data && data.type === 'server_stats') {
                        const newPoint = {
                            ts: Date.now(),
                            cpu: Math.max(0, parseFloat(data.cpu) || 0),
                            mem: Math.max(0, parseFloat(data.memory) || 0),
                            disk: Math.max(0, parseFloat(data.disk) || 0)
                        };
                        setHistory(prev => {
                            const updated = [...prev, newPoint];
                            return updated.slice(-MAX_POINTS);
                        });
                        setStats({ cpu: newPoint.cpu, memory: newPoint.mem, disk: newPoint.disk, lastUpdate: new Date() });
                    }
                } catch (e) {}
            };
            ws.onclose = () => setTimeout(connect, 2000);
        };
        connect();
        return () => ws && ws.close();
    }, [server.containerId, pageData.wsToken]);

    // Canvas Drawing loop
    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;

        const draw = () => {
            const ctx = canvas.getContext('2d');
            const dpr = window.devicePixelRatio || 1;
            const rect = canvas.getBoundingClientRect();
            const width = rect.width;
            const height = rect.height;

            canvas.width = width * dpr;
            canvas.height = height * dpr;
            ctx.scale(dpr, dpr);

            ctx.clearRect(0, 0, width, height);
            ctx.fillStyle = '#0a0a0c'; // Matches neural-950/900 roughly
            ctx.fillRect(0, 0, width, height);

            // Grid
            ctx.strokeStyle = 'rgba(255,255,255,0.05)';
            ctx.lineWidth = 1;
            for (let i = 0; i <= 4; i++) {
                const y = 10 + (height - 20) * (i / 4);
                ctx.beginPath();
                ctx.moveTo(0, y);
                ctx.lineTo(width, y);
                ctx.stroke();
            }

            if (history.length < 2) return;

            const clamp = (v) => Math.max(0, Math.min(100, v));
            const getX = (i) => (width / (MAX_POINTS - 1)) * (i + (MAX_POINTS - history.length));
            const getY = (percent) => 10 + (height - 20) * (1 - (clamp(percent) / 100));

            const drawLine = (getData, color, fillGradient) => {
                ctx.beginPath();
                history.forEach((pt, i) => {
                    const x = getX(i);
                    const y = getY(getData(pt));
                    if (i === 0) ctx.moveTo(x, y);
                    else ctx.lineTo(x, y);
                });
                ctx.strokeStyle = color;
                ctx.lineWidth = 2;
                ctx.lineJoin = 'round';
                ctx.stroke();

                // Optional fill
                if (fillGradient) {
                    ctx.lineTo(getX(history.length - 1), height);
                    ctx.lineTo(getX(0), height);
                    ctx.closePath();
                    const grad = ctx.createLinearGradient(0, 0, 0, height);
                    grad.addColorStop(0, fillGradient);
                    grad.addColorStop(1, 'transparent');
                    ctx.fillStyle = grad;
                    ctx.fill();
                }
            };

            // Disk %
            drawLine(p => (p.disk / diskLimit) * 100, '#f59e0b', 'rgba(245, 158, 11, 0.05)');
            // Mem %
            drawLine(p => (p.mem / memoryLimit) * 100, '#3b82f6', 'rgba(59, 130, 246, 0.05)');
            // CPU %
            drawLine(p => p.cpu, '#22c55e', 'rgba(34, 197, 94, 0.1)');
        };

        draw();
        window.addEventListener('resize', draw);
        return () => window.removeEventListener('resize', draw);
    }, [history, memoryLimit, diskLimit]);

    return (
        <ReactAppShell pageData={pageData} subtitle="Resource Timeline">
            <PageContentBlock title="Resource Timeline" description="Real-time performance monitoring across CPU, Memory and Disk.">
                
                <div className="bg-neutral-900 border border-neutral-800 rounded-2xl p-6 shadow-xl overflow-hidden">
                    <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
                        <div className="flex gap-6">
                            <div className="flex items-center gap-2">
                                <div className="w-3 h-3 rounded-full bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]"></div>
                                <span className="text-xs font-bold text-neutral-300 uppercase tracking-widest">CPU Used</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <div className="w-3 h-3 rounded-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]"></div>
                                <span className="text-xs font-bold text-neutral-300 uppercase tracking-widest">Memory Used</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <div className="w-3 h-3 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]"></div>
                                <span className="text-xs font-bold text-neutral-300 uppercase tracking-widest">Disk Used</span>
                            </div>
                        </div>
                        <div className="text-[10px] font-mono text-neutral-500">
                            Last Update: {stats.lastUpdate ? stats.lastUpdate.toLocaleTimeString() : 'Waiting...'}
                        </div>
                    </div>

                    <div className="relative group">
                        <canvas 
                            ref={canvasRef} 
                            className="w-full h-[360px] cursor-crosshair rounded-lg"
                            style={{ imageRendering: 'auto' }}
                        ></canvas>
                        
                        {/* Overlay markers */}
                        <div className="absolute top-4 right-4 pointer-events-none space-y-2">
                            <div className="bg-neutral-950/80 backdrop-blur-md border border-neutral-700/50 rounded-lg px-3 py-2 text-right">
                                <div className="text-[10px] text-neutral-500 font-bold uppercase tracking-tighter">Current CPU</div>
                                <div className="text-lg font-black text-white">{stats.cpu.toFixed(1)}%</div>
                            </div>
                            <div className="bg-neutral-950/80 backdrop-blur-md border border-neutral-700/50 rounded-lg px-3 py-2 text-right">
                                <div className="text-[10px] text-neutral-500 font-bold uppercase tracking-tighter">Current Memory</div>
                                <div className="text-lg font-black text-white">{Math.round(stats.memory)} MB</div>
                            </div>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-8 pt-8 border-t border-neutral-800">
                        <div className="space-y-1">
                            <div className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest">CPU Limit</div>
                            <div className="text-neutral-200 font-mono">Unrestricted</div>
                        </div>
                        <div className="space-y-1">
                            <div className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest">Memory Limit</div>
                            <div className="text-neutral-200 font-mono">{memoryLimit} MB</div>
                        </div>
                        <div className="space-y-1">
                            <div className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest">Disk Quota</div>
                            <div className="text-neutral-200 font-mono">{diskLimit} MB</div>
                        </div>
                    </div>
                </div>

            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerTimelinePage;

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <ServerTimelinePage pageData={data} />
        </ThemeProvider>
    );
}