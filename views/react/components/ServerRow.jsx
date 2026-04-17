import React from 'react';
import { Link } from 'react-router-dom';

function formatLimit(mb) {
    if (!mb || mb <= 0) return 'N/A';
    if (mb >= 1024) return `${(mb / 1024).toFixed(mb % 1024 === 0 ? 0 : 1)} GB`;
    return `${mb} MB`;
}

export default function ServerRow({ server, isAdminDashboard }) {
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
        <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-5 hover:border-neutral-500 transition-colors duration-200 flex flex-col md:flex-row md:items-center justify-between group">
            <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 mb-1">
                    <h3 className="text-lg font-bold text-neutral-100 truncate group-hover:text-primary-400 transition-colors">
                        {server.name}
                    </h3>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-semibold uppercase tracking-wide ${statusColor}`}>
                        {statusLabel}
                    </span>
                </div>
                <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs text-neutral-500 font-mono truncate">
                        {server.containerId?.substring(0, 12)}
                    </span>
                    {isAdminDashboard && server.owner && (
                         <div className="flex items-center gap-1.5 ml-2 pl-2 border-l border-neutral-700">
                            <i className="bi bi-person text-[10px] text-neutral-500"></i>
                            <span className="text-[10px] font-bold text-neutral-400 uppercase tracking-tighter">
                                {server.owner.username}
                            </span>
                        </div>
                    )}
                </div>
            </div>

            <div className="mt-4 md:mt-0 flex gap-4 md:ml-6 shrink-0">
                <div className="text-center">
                    <div className="text-xs text-neutral-500 uppercase font-bold tracking-wider mb-0.5">CPU</div>
                    <div className="text-sm font-mono text-neutral-200">{server.cpu ? `${server.cpu}%` : 'N/A'}</div>
                </div>
                <div className="text-center">
                    <div className="text-xs text-neutral-500 uppercase font-bold tracking-wider mb-0.5">Memory</div>
                    <div className="text-sm font-mono text-neutral-200">{formatLimit(server.memory)}</div>
                </div>
                <div className="text-center">
                    <div className="text-xs text-neutral-500 uppercase font-bold tracking-wider mb-0.5">Disk</div>
                    <div className="text-sm font-mono text-neutral-200">{formatLimit(server.disk)}</div>
                </div>
                <div className="ml-2 pl-4 border-l border-neutral-700 flex flex-col justify-center">
                    <a href={`/server/${server.containerId}`} className="text-neutral-300 hover:text-white bg-neutral-700 hover:bg-neutral-600 px-4 py-2 rounded font-semibold text-sm transition-colors">
                        Manage
                    </a>
                </div>
            </div>
        </div>
    );
}
