import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'connectors-check';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function fmt(value, digits = 1) {
    const num = Number(value || 0);
    if (!Number.isFinite(num)) return '0';
    return num.toFixed(digits);
}

function fmtTime(value) {
    if (!value) return 'Never';
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) return 'Never';
    return dt.toLocaleString();
}

const getSeverityTheme = (pct) => {
    if (pct >= 95) return { bg: 'bg-red-500/20', bar: 'bg-red-500', text: 'text-red-400' };
    if (pct >= 80) return { bg: 'bg-yellow-500/20', bar: 'bg-yellow-500', text: 'text-yellow-400' };
    return { bg: 'bg-primary-500/20', bar: 'bg-primary-500', text: 'text-primary-400' };
};

function ConnectorGridCard({ item }) {
    const { connector, metrics, isOnline, statusData } = item;
    const ramTheme = getSeverityTheme(metrics.memoryUsagePct);
    const diskTheme = getSeverityTheme(metrics.diskUsagePct);

    return (
        <div className="bg-neutral-800/50 border border-neutral-700/50 rounded-2xl p-6 hover:border-neutral-600 transition-all group shadow-xl">
            <div className="flex justify-between items-start mb-6">
                <div>
                    <h3 className="text-lg font-bold text-white group-hover:text-primary-400 transition-colors uppercase tracking-tight">
                        {connector.name}
                    </h3>
                    <div className="text-xs text-neutral-500 font-mono mt-1">
                        {connector.fqdn} {connector.location?.shortName && <span className="text-neutral-700 mx-1">|</span>} {connector.location?.shortName}
                    </div>
                </div>
                <div className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest flex items-center gap-2 ${isOnline ? 'bg-green-500/10 text-green-500 border border-green-500/20' : 'bg-neutral-700 text-neutral-400 border border-neutral-600'}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${isOnline ? 'bg-green-500 animate-pulse' : 'bg-neutral-500'}`}></span>
                    {isOnline ? 'Online' : 'Offline'}
                </div>
            </div>

            <div className="grid grid-cols-2 gap-6 mb-6">
                {/* RAM Metric */}
                <div className="space-y-2">
                    <div className="flex justify-between items-end">
                        <span className="text-[10px] font-black text-neutral-500 uppercase tracking-widest">RAM Capacity</span>
                        <span className={`text-xs font-bold ${ramTheme.text}`}>{fmt(metrics.memoryFreeGb)} GB Free</span>
                    </div>
                    <div className="h-2 bg-neutral-900 rounded-full overflow-hidden">
                        <div 
                            className={`h-full transition-all duration-1000 ease-out ${ramTheme.bar}`} 
                            style={{ width: `${Math.min(100, metrics.memoryUsagePct)}%` }}
                        ></div>
                    </div>
                    <div className="flex justify-between text-[10px] font-bold">
                        <span className="text-neutral-500">{fmt(metrics.memoryUsedGb)} used</span>
                        <span className="text-neutral-400">{fmt(metrics.memoryCapGb)} cap</span>
                    </div>
                </div>

                {/* Disk Metric */}
                <div className="space-y-2">
                    <div className="flex justify-between items-end">
                        <span className="text-[10px] font-black text-neutral-500 uppercase tracking-widest">Disk Capacity</span>
                        <span className={`text-xs font-bold ${diskTheme.text}`}>{fmt(metrics.diskFreeGb)} GB Free</span>
                    </div>
                    <div className="h-2 bg-neutral-900 rounded-full overflow-hidden">
                        <div 
                            className={`h-full transition-all duration-1000 ease-out ${diskTheme.bar}`} 
                            style={{ width: `${Math.min(100, metrics.diskUsagePct)}%` }}
                        ></div>
                    </div>
                    <div className="flex justify-between text-[10px] font-bold">
                        <span className="text-neutral-500">{fmt(metrics.diskUsedGb)} used</span>
                        <span className="text-neutral-400">{fmt(metrics.diskCapGb)} cap</span>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-3 gap-4 py-4 border-t border-neutral-700/30">
                <div>
                    <div className="text-[9px] font-black text-neutral-600 uppercase tracking-widest mb-1">Allocations</div>
                    <div className="text-sm font-bold text-neutral-200">
                        {metrics.freeAllocations} <span className="text-neutral-600 text-[10px]">/ {metrics.totalAllocations}</span>
                    </div>
                </div>
                <div>
                    <div className="text-[9px] font-black text-neutral-600 uppercase tracking-widest mb-1">CPU Host</div>
                    <div className="text-sm font-bold text-neutral-200">{fmt(metrics.cpuLivePercent, 1)}%</div>
                </div>
                <div>
                    <div className="text-[9px] font-black text-neutral-600 uppercase tracking-widest mb-1">CPU Allocs</div>
                    <div className="text-sm font-bold text-neutral-200">{fmt(metrics.cpuAllocatedCores, 2)}<span className="text-[10px] text-neutral-600 ms-1">C</span></div>
                </div>
            </div>

            <div className="mt-4 pt-4 border-t border-neutral-700/30 flex items-center justify-between">
                <span className="text-[10px] text-neutral-500 font-bold uppercase tracking-wider">
                    Last Seen: {fmtTime(statusData?.lastSeen)}
                </span>
                <a 
                    href={`/admin/connectors/${connector.id}`}
                    className="text-[10px] font-black text-primary-400 hover:text-primary-300 uppercase tracking-[0.2em] transition-colors"
                >
                    Manage Node
                </a>
            </div>
        </div>
    );
}

export function ConnectorsCheckPage({ pageData = data }) {
    const items = pageData.cards || [];
    const filters = pageData.filters || {};

    return (
        <ReactAppShell pageData={pageData} subtitle="Infrastructure Health">
            <PageContentBlock 
                title="Connectors Check" 
                description="Monitor real-time resource availability and node health across your global connector network."
            >
                {/* Filter Panel */}
                <div className="bg-neutral-800 border border-neutral-700 rounded-2xl p-6 mb-8 shadow-2xl">
                    <form method="GET" action="/connectors-check" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4 items-end">
                        <div className="lg:col-span-2">
                            <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-2">Search Network</label>
                            <input 
                                type="text" 
                                name="search" 
                                defaultValue={filters.search}
                                placeholder="Name, FQDN or Location..."
                                className="w-full bg-neutral-900 border border-neutral-700 rounded-xl px-4 py-2.5 text-sm text-white focus:border-primary-500 transition-colors outline-none"
                            />
                        </div>
                        <div>
                            <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-2">Node Status</label>
                            <select 
                                name="status" 
                                defaultValue={filters.status}
                                className="w-full bg-neutral-900 border border-neutral-700 rounded-xl px-4 py-2.5 text-sm text-white focus:border-primary-500 transition-colors outline-none"
                            >
                                <option value="all">All States</option>
                                <option value="online">Online Only</option>
                                <option value="offline">Offline Only</option>
                            </select>
                        </div>
                        <div>
                            <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-2">Min RAM (GB)</label>
                            <input 
                                type="number" 
                                step="0.1"
                                name="minFreeRamGb" 
                                defaultValue={filters.minFreeRamGb}
                                className="w-full bg-neutral-900 border border-neutral-700 rounded-xl px-4 py-2.5 text-sm text-white focus:border-primary-500 transition-colors outline-none"
                            />
                        </div>
                        <div>
                            <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-2">Min Alloc Free</label>
                            <input 
                                type="number" 
                                name="minFreeAllocations" 
                                defaultValue={filters.minFreeAllocations}
                                className="w-full bg-neutral-900 border border-neutral-700 rounded-xl px-4 py-2.5 text-sm text-white focus:border-primary-500 transition-colors outline-none"
                            />
                        </div>
                        <div className="flex gap-2">
                            <button type="submit" className="flex-1 bg-primary-600 hover:bg-primary-500 text-white font-black text-[10px] uppercase tracking-widest py-3 rounded-xl transition-all shadow-lg shadow-primary-900/20 active:scale-95">
                                Apply
                            </button>
                            <a href="/connectors-check" className="p-3 bg-neutral-700 hover:bg-neutral-600 text-white rounded-xl transition-colors">
                                <i className="bi bi-arrow-counterclockwise"></i>
                            </a>
                        </div>
                    </form>
                    <div className="mt-4 flex items-center justify-between text-[10px] font-bold uppercase tracking-wider">
                        <div className="text-neutral-500">
                            Filtered Analysis: <span className="text-neutral-200">{items.length}</span> nodes found
                        </div>
                        <div className="text-neutral-500">
                            Total Cluster Size: <span className="text-neutral-200">{pageData.totalCards}</span>
                        </div>
                    </div>
                </div>

                {/* Items Grid */}
                {items.length === 0 ? (
                    <div className="py-20 flex flex-col items-center justify-center bg-neutral-800/20 border border-neutral-800 border-dashed rounded-3xl">
                        <i className="bi bi-activity text-5xl text-neutral-700 mb-4"></i>
                        <h3 className="text-lg font-bold text-neutral-400">No connectors match your parameters.</h3>
                        <p className="text-sm text-neutral-600 mt-1">Try relaxing your RAM or Allocation requirements.</p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                        {items.map((item, idx) => (
                            <div key={item.connector.id || idx} className="animate-in fade-in slide-in-from-bottom-4 duration-500" style={{ animationDelay: `${idx * 40}ms` }}>
                                <ConnectorGridCard item={item} />
                            </div>
                        ))}
                    </div>
                )}
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ConnectorsCheckPage;

if (root) {
    root.render(
        <BrowserRouter>
            <ConnectorsCheckPage pageData={data} />
        </BrowserRouter>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
