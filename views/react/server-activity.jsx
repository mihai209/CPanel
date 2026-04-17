import React from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-activity';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function formatMetaDate(value) {
    if (!value) return '';
    const date = new Date(value);
    return isNaN(date.getTime()) ? '' : date.toLocaleString();
}

function getActivityTone(action) {
    const val = String(action || '').trim();
    if (val.includes('crash') || val.includes('error') || val.includes('denied')) return 'danger';
    if (val.includes('start') || val.includes('success') || val.includes('transition')) return 'success';
    if (val.includes('mismatch') || val.includes('recovery')) return 'warning';
    return 'neutral';
}

function getActivitySummary(log) {
    const action = String(log?.action || '').trim();
    const metadata = log?.metadata || {};
    
    if (action === 'server:state.transition' || action === 'server:state.mismatch') {
        const prev = metadata.previousStatus || 'unknown';
        const next = metadata.nextStatus || 'unknown';
        const src = metadata.source || 'system';
        const reason = metadata.reason ? ` · ${metadata.reason}` : '';
        return `${prev.toUpperCase()} → ${next.toUpperCase()} (via ${src})${reason}`;
    }
    
    if (action === 'server:recovery.policy') return `${metadata.playbook || 'policy'} → ${metadata.action || 'unknown'}`;
    if (action === 'server:recovery.auto') return `${metadata.action || 'start'} (recovery after crash)`;
    if (action === 'server:power.action') return `${metadata.powerAction || 'unknown'} requested`;
    
    if (action === 'server:debug.crash') {
        const exit = metadata.exitCode !== undefined ? `exit ${metadata.exitCode}` : 'no exit code';
        return metadata.oomKilled ? `${exit} · OOM KILLED` : exit;
    }

    return [log?.targetType, log?.targetId].filter(Boolean).join(' / ') || '-';
}

function ToneBadge({ tone, children }) {
    const colors = {
        success: 'bg-green-500/10 text-green-500 border-green-500/20',
        danger: 'bg-red-500/10 text-red-500 border-red-500/20',
        warning: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
        neutral: 'bg-neutral-800 text-neutral-400 border-neutral-700',
    };
    return (
        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${colors[tone] || colors.neutral}`}>
            {children}
        </span>
    );
}

export function ServerActivityPage({ pageData = data }) {
    const server = pageData.server || {};
    const logs = pageData.logs || [];
    const changeLogs = pageData.changeLogs || [];
    const [isClearing, setIsClearing] = React.useState(false);

    const handleClearLogs = async () => {
        if (!window.confirm('Are you sure you want to PERMANENTLY clear all activity and change logs for this server? This action cannot be undone.')) {
            return;
        }

        setIsClearing(true);
        try {
            const response = await fetch(`/server/${server.containerId}/activity/clear`, {
                method: 'POST',
                headers: { 'Accept': 'application/json' }
            });
            const payload = await response.json();
            if (payload.success) {
                window.location.reload();
            } else {
                alert(payload.error || 'Failed to clear logs.');
                setIsClearing(false);
            }
        } catch (err) {
            alert('An error occurred while clearing logs.');
            setIsClearing(false);
        }
    };

    const canClear = pageData.user?.isAdmin || (pageData.permissions && pageData.permissions['server.activity.clear']);

    return (
        <ReactAppShell pageData={pageData} subtitle="Activity">
            <PageContentBlock title="Server Activity" description="Tracking all events and state changes for your server.">
                
                {canClear && (
                    <div className="flex justify-end mb-6">
                        <button 
                            onClick={handleClearLogs}
                            disabled={isClearing}
                            className="bg-red-900/30 hover:bg-red-600 border border-red-500/50 text-red-200 hover:text-white font-black text-[10px] uppercase tracking-[0.2em] py-2.5 px-5 rounded-xl transition-all flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-red-900/20"
                        >
                            <i className={`bi ${isClearing ? 'bi-hourglass-split' : 'bi-trash3-fill'}`}></i>
                            {isClearing ? 'Clearing History...' : 'Clear Activity History'}
                        </button>
                    </div>
                )}
                
                {/* Changes Table */}
                <div className="bg-neutral-900 border border-neutral-800 rounded-xl overflow-hidden mb-8 shadow-sm">
                    <div className="bg-neutral-800/50 px-5 py-4 border-b border-neutral-800">
                        <h3 className="text-xs font-black text-neutral-400 uppercase tracking-[0.2em]">What Changed</h3>
                    </div>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest border-b border-neutral-800">
                                    <th className="px-6 py-4">When</th>
                                    <th className="px-6 py-4">Actor</th>
                                    <th className="px-6 py-4">Category</th>
                                    <th className="px-6 py-4">Summary</th>
                                    <th className="px-6 py-4">Diff</th>
                                </tr>
                            </thead>
                            <tbody className="text-sm">
                                {changeLogs.length === 0 ? (
                                    <tr>
                                        <td colSpan="5" className="px-6 py-10 text-center text-neutral-500 italic">No configuration changes recorded yet.</td>
                                    </tr>
                                ) : (
                                    changeLogs.map((entry, idx) => (
                                        <tr key={idx} className="border-b border-neutral-800/50 hover:bg-white/[0.02] transition-colors">
                                            <td className="px-6 py-4 text-neutral-400 whitespace-nowrap">{new Date(entry.createdAt).toLocaleString()}</td>
                                            <td className="px-6 py-4">
                                                <div className="flex items-center gap-2">
                                                    <div className="w-6 h-6 rounded-full bg-neutral-800 flex items-center justify-center text-[10px] font-bold text-primary-400">
                                                        {entry.actor?.username?.charAt(0).toUpperCase() || 'S'}
                                                    </div>
                                                    <span className="text-neutral-200">{entry.actor?.username || 'system'}</span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className="bg-neutral-800 text-neutral-400 px-2 py-0.5 rounded text-[10px] font-mono border border-neutral-700">
                                                    {entry.category || '-'}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="font-bold text-neutral-200">{entry.summary || entry.changeKey || '-'}</div>
                                                {entry.changeKey && <div className="text-[10px] text-neutral-500 font-mono mt-0.5">{entry.changeKey}</div>}
                                            </td>
                                            <td className="px-6 py-4 max-w-xs">
                                                <div className="text-[10px] space-y-1">
                                                    <div className="flex gap-2">
                                                        <span className="text-red-500/50 font-bold uppercase w-10">Before:</span>
                                                        <code className="text-neutral-500 truncate block">{JSON.stringify(entry.beforeValue)}</code>
                                                    </div>
                                                    <div className="flex gap-2">
                                                        <span className="text-green-500/50 font-bold uppercase w-10">After:</span>
                                                        <code className="text-neutral-300 truncate block">{JSON.stringify(entry.afterValue)}</code>
                                                    </div>
                                                </div>
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Activity Table */}
                <div className="bg-neutral-900 border border-neutral-800 rounded-xl overflow-hidden shadow-sm">
                    <div className="bg-neutral-800/50 px-5 py-4 border-b border-neutral-800">
                        <h3 className="text-xs font-black text-neutral-400 uppercase tracking-[0.2em]">Activity Log</h3>
                    </div>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest border-b border-neutral-800">
                                    <th className="px-6 py-4">When</th>
                                    <th className="px-6 py-4">Actor</th>
                                    <th className="px-6 py-4 text-center">Action</th>
                                    <th className="px-6 py-4">Summary</th>
                                    <th className="px-6 py-4 text-right">IP Address</th>
                                </tr>
                            </thead>
                            <tbody className="text-sm">
                                {logs.length === 0 ? (
                                    <tr>
                                        <td colSpan="5" className="px-6 py-10 text-center text-neutral-500 italic">No activity logs found.</td>
                                    </tr>
                                ) : (
                                    logs.map((log, idx) => (
                                        <tr key={idx} className="border-b border-neutral-800/50 hover:bg-white/[0.02] transition-colors">
                                            <td className="px-6 py-4 text-neutral-400 whitespace-nowrap">{new Date(log.createdAt).toLocaleString()}</td>
                                            <td className="px-6 py-4">
                                                <span className="text-neutral-200 font-medium">{log.actor?.username || 'system'}</span>
                                            </td>
                                            <td className="px-6 py-4 text-center">
                                                <ToneBadge tone={getActivityTone(log.action)}>
                                                    {(log.action || '').split(':').pop().replace(/\./g, ' ')}
                                                </ToneBadge>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="text-neutral-300">{getActivitySummary(log)}</div>
                                                {log.metadata?.reason && (
                                                    <div className="text-[10px] text-neutral-500 italic mt-1 flex items-center gap-1">
                                                        <i className="bi bi-info-circle"></i> {log.metadata.reason}
                                                    </div>
                                                )}
                                            </td>
                                            <td className="px-6 py-4 text-right text-neutral-500 font-mono text-xs">
                                                {log.ip || '–'}
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerActivityPage;

if (root) {
    root.render(<ServerActivityPage pageData={data} />);
}
