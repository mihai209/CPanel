import React from 'react';
import { Link } from 'react-router-dom';

function formatLimit(mb) {
    if (!mb || mb <= 0) return 'N/A';
    if (mb >= 1024) return `${(mb / 1024).toFixed(mb % 1024 === 0 ? 0 : 1)} GB`;
    return `${mb} MB`;
}

export default function ServerRow({ server, isAdminDashboard, showResourcePills = true }) {
    const rawStatus = String(server.status || 'unknown').toLowerCase();
    
    let statusColor = 'bg-neutral-600 text-neutral-200';
    let statusLabel = rawStatus;

    if (server.isSuspended) {
        statusColor = 'bg-red-600 text-white';
        statusLabel = 'suspended';
    } else if (rawStatus === 'running') {
        statusColor = 'bg-green-600 text-white';
    } else if (rawStatus === 'stopped') {
        statusColor = 'bg-red-600 text-white';
    } else if (rawStatus === 'installing') {
        statusColor = 'bg-yellow-500 text-neutral-900';
    }

    return (
        <div className="bg-neutral-900/50 backdrop-blur-sm border border-neutral-800/80 rounded-[1.5rem] p-6 hover:border-primary-500/30 hover:bg-neutral-800/40 transition-all duration-300 flex flex-col lg:flex-row lg:items-center justify-between group shadow-lg hover:shadow-primary-900/5">
            <div className="flex-1 min-w-0">
                <div className="flex items-center gap-4 mb-2">
                    <div className={`w-2.5 h-2.5 rounded-full ${server.isSuspended ? 'bg-red-500' : (rawStatus === 'running' ? 'bg-green-500' : 'bg-neutral-700')} shadow-[0_0_10px_rgba(34,197,94,0.3)]`}></div>
                    <h3 className="text-lg font-black text-neutral-100 truncate group-hover:text-primary-400 transition-colors tracking-tight">
                        {server.name}
                    </h3>
                    <span className={`text-[10px] px-3 py-1 rounded-full font-black uppercase tracking-[0.1em] ${statusColor} bg-opacity-10 ring-1 ring-inset ring-current`}>
                        {statusLabel}
                    </span>
                </div>
                <div className="flex items-center gap-3 mt-2">
                    <span className="text-[10px] text-neutral-500 font-black uppercase tracking-widest bg-neutral-800/50 px-2 py-0.5 rounded">
                        {server.containerId?.substring(0, 12)}
                    </span>
                    {isAdminDashboard && server.owner && (
                         <div className="flex items-center gap-2 pl-3 border-l border-neutral-800">
                            <i className="bi bi-person-badge text-xs text-primary-500/70"></i>
                            <span className="text-[10px] font-black text-neutral-400 uppercase tracking-widest">
                                {server.owner.username}
                            </span>
                        </div>
                    )}
                </div>
            </div>

            <div className="mt-6 lg:mt-0 flex flex-wrap sm:flex-nowrap items-center gap-6 lg:ml-8 shrink-0">
                {showResourcePills && (
                    <>
                        <div className="flex-1 sm:flex-none">
                            <div className="text-[10px] text-neutral-500 uppercase font-black tracking-widest mb-1 opacity-60">CPU Usage</div>
                            <div className="text-sm font-black text-neutral-200 tabular-nums">{server.cpu ? `${server.cpu}%` : '0%'}</div>
                        </div>
                        <div className="w-px h-8 bg-neutral-800 hidden sm:block"></div>
                        <div className="flex-1 sm:flex-none">
                            <div className="text-[10px] text-neutral-500 uppercase font-black tracking-widest mb-1 opacity-60">Memory</div>
                            <div className="text-sm font-black text-neutral-200 tabular-nums">{formatLimit(server.memory)}</div>
                        </div>
                        <div className="w-px h-8 bg-neutral-800 hidden sm:block"></div>
                        <div className="flex-1 sm:flex-none">
                            <div className="text-[10px] text-neutral-500 uppercase font-black tracking-widest mb-1 opacity-60">Storage</div>
                            <div className="text-sm font-black text-neutral-200 tabular-nums">{formatLimit(server.disk)}</div>
                        </div>
                    </>
                )}
                
                <div className="w-full sm:w-auto mt-4 sm:mt-0 sm:ml-4">
                    <a href={`/server/${server.containerId}`} className="flex items-center justify-center gap-2 bg-neutral-800 hover:bg-primary-600 text-neutral-100 hover:text-white px-6 py-3 rounded-xl font-black text-[10px] uppercase tracking-[0.2em] transition-all duration-300 shadow-xl shadow-black/20 hover:shadow-primary-900/20 active:scale-95">
                        Manage <i className="bi bi-arrow-right-short text-lg"></i>
                    </a>
                </div>
            </div>
        </div>
    );
}
