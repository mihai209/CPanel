import React from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-backups';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function formatBytes(value) {
    const bytes = Math.max(0, Number(value) || 0);
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let current = bytes;
    let index = 0;
    while (current >= 1024 && index < units.length - 1) {
        current /= 1024;
        index += 1;
    }
    return `${current >= 100 || index === 0 ? current.toFixed(0) : current.toFixed(2)} ${units[index]}`;
}

function formatWhen(value) {
    if (!value) return 'Never';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Never' : date.toLocaleString();
}

function statusTone(status) {
    const value = String(status || '').toLowerCase();
    if (['completed', 'success', 'ready'].includes(value)) return 'success';
    if (['queued', 'running', 'retrying'].includes(value)) return 'warning';
    return 'danger';
}

function statusColorClass(status) {
    const tone = statusTone(status);
    if (tone === 'success') return 'bg-green-600/20 text-green-400 border border-green-600/30';
    if (tone === 'warning') return 'bg-yellow-600/20 text-yellow-400 border border-yellow-600/30';
    return 'bg-red-600/20 text-red-400 border border-red-600/30';
}

export function ServerBackupsPage({ pageData = data }) {
    const server = pageData.server || {};
    const backups = Array.isArray(pageData.backups) ? pageData.backups : [];
    const driveState = pageData.googleDriveState || {};
    const permissions = pageData.permissions || {};
    const policy = pageData.backupPolicy || {};
    const actions = pageData.actions || {};

    const inputClass = "w-full bg-neutral-900 border border-neutral-700/50 rounded p-2.5 text-sm text-neutral-200 focus:ring-2 focus:ring-primary-500 focus:border-transparent outline-none transition-shadow";
    const labelClass = "block text-xs font-bold text-neutral-400 uppercase tracking-wide mb-1.5";

    const [isClearing, setIsClearing] = React.useState(false);

    const handleClearHistory = async () => {
        if (!window.confirm('Are you sure you want to clear the backup history for this server? This only removes the database records; actual files in Google Drive will not be deleted.')) {
            return;
        }

        setIsClearing(true);
        try {
            const response = await fetch(`/server/${server.containerId}/backups/clear`, {
                method: 'POST',
                headers: { 'Accept': 'application/json' }
            });
            const payload = await response.json();
            if (payload.success) {
                window.location.reload();
            } else {
                alert(payload.error || 'Failed to clear backup history.');
                setIsClearing(false);
            }
        } catch (err) {
            alert('An error occurred while clearing backup history.');
            setIsClearing(false);
        }
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Backups">
            <PageContentBlock 
                title="Backups" 
                description="Review backup history, connect Google Drive for storage, and trigger fresh snapshots." 
                eyebrow="Recovery"
            >
                <div className="flex justify-end gap-3 mb-6">
                    {permissions.canManageBackups && (
                        <button 
                            onClick={handleClearHistory}
                            disabled={isClearing}
                            className="bg-red-900/10 hover:bg-red-600/20 text-red-400 border border-red-500/30 font-semibold py-2 px-4 rounded transition-colors text-sm flex items-center gap-2 disabled:opacity-50"
                        >
                            <i className={`bi ${isClearing ? 'bi-hourglass-split' : 'bi-trash3'}`}></i> 
                            {isClearing ? 'Clearing...' : 'Clear History'}
                        </button>
                    )}
                    {permissions.canManageBackups ? (
                         <form method="POST" action={actions.run}>
                             <button type="submit" className="bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm flex items-center gap-2">
                                 <i className="bi bi-hdd-rack"></i> Create Backup
                             </button>
                         </form>
                    ) : null}
                </div>

                {pageData.success && (
                    <div className="bg-green-600/20 border border-green-600/50 text-green-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3">
                        <i className="bi bi-check-circle-fill text-green-500"></i>
                        {pageData.success}
                    </div>
                )}
                {pageData.error && (
                    <div className="bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3">
                        <i className="bi bi-exclamation-triangle-fill text-red-500"></i>
                        {pageData.error}
                    </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start mb-6">
                    {/* Drive Integration */}
                    <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6">
                        <div className="flex items-center gap-3 mb-6">
                            <i className="bi bi-google text-2xl text-primary-400"></i>
                            <h2 className="text-lg font-bold text-neutral-100">Drive Integration</h2>
                        </div>
                        <div className="flex flex-col gap-4 mb-4">
                            <div className="flex justify-between items-center border-b border-neutral-700/50 pb-3">
                                <span className="text-sm font-semibold text-neutral-400">Server</span>
                                <strong className="text-neutral-200">{server.name || 'Server'}</strong>
                            </div>
                            <div className="flex justify-between items-center border-b border-neutral-700/50 pb-3">
                                <span className="text-sm font-semibold text-neutral-400">Drive Ready</span>
                                <strong className={driveState.ready ? 'text-green-400' : 'text-neutral-400'}>{driveState.ready ? 'Ready' : 'Needs setup'}</strong>
                            </div>
                            <div className="flex justify-between items-center pb-2">
                                <span className="text-sm font-semibold text-neutral-400">Last Run</span>
                                <strong className="text-neutral-200 font-mono text-sm">{formatWhen(policy.lastRunAt)}</strong>
                            </div>
                        </div>
                        <p className="text-sm text-neutral-400 italic mb-4">{driveState.statusText || 'Google Drive state is unavailable.'}</p>
                        {driveState.canConnect ? (
                            <a href={actions.connectGoogle || driveState.connectUrl} className="inline-block bg-neutral-700 hover:bg-neutral-600 text-white font-semibold py-2 px-6 rounded transition-colors text-sm text-center w-full shadow-sm">
                                Connect Google Drive
                            </a>
                        ) : null}
                    </div>

                    {/* Policy */}
                    <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6 flex flex-col h-full">
                        <div className="flex items-center gap-3 mb-6">
                            <i className="bi bi-calendar-event text-2xl text-primary-400"></i>
                            <h2 className="text-lg font-bold text-neutral-100">Automated Policy</h2>
                        </div>
                        <form method="POST" action={actions.savePolicy} className="flex flex-col gap-5 flex-1">
                            <label className="flex items-start gap-3 cursor-pointer group mb-2">
                                <input 
                                    type="checkbox" 
                                    name="enabled" 
                                    defaultChecked={Boolean(policy.autoEnabled)} 
                                    className="w-5 h-5 mt-0.5 rounded border-neutral-600 bg-neutral-900 text-primary-600 focus:ring-primary-600 focus:ring-offset-neutral-800"
                                />
                                <div>
                                    <span className="block text-sm font-bold text-neutral-200 group-hover:text-white transition-colors">Enable scheduled backups</span>
                                    <span className="block text-xs text-neutral-500 mt-1">Automatically generates periodic backups in the background.</span>
                                </div>
                            </label>
                            
                            <label className="mb-2">
                                <span className={labelClass}>Interval in minutes</span>
                                <div className="relative">
                                    <input 
                                        type="number" 
                                        name="intervalMinutes" 
                                        min="5" 
                                        max="10080" 
                                        defaultValue={policy.intervalMinutes || 360} 
                                        className={inputClass} 
                                    />
                                    <div className="absolute inset-y-0 right-0 flex items-center pr-4 pointer-events-none text-neutral-500 text-xs font-bold">MIN</div>
                                </div>
                            </label>
                            
                            <div className="mt-auto flex justify-end flex-wrap pt-4">
                                <button type="submit" className="w-full bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50" disabled={!permissions.canManageBackupPolicy}>
                                    Save Policy
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                {/* Active Job Alert */}
                {pageData.activeJob ? (
                    <div className="bg-primary-900/20 border-2 border-primary-600/50 rounded-lg p-6 mb-6">
                        <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                            <i className="bi bi-arrow-repeat animate-spin text-primary-400"></i> Active Backup Job
                        </h2>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div className="bg-neutral-900/50 p-3 rounded">
                                <span className="block text-xs font-bold text-neutral-500 uppercase">Status</span>
                                <strong className="block text-sm text-primary-300 mt-1">{pageData.activeJob.status}</strong>
                            </div>
                            <div className="bg-neutral-900/50 p-3 rounded">
                                <span className="block text-xs font-bold text-neutral-500 uppercase">Type</span>
                                <strong className="block text-sm text-neutral-200 mt-1">{pageData.activeJob.type}</strong>
                            </div>
                            <div className="bg-neutral-900/50 p-3 rounded">
                                <span className="block text-xs font-bold text-neutral-500 uppercase">Updated</span>
                                <strong className="block text-sm text-neutral-200 mt-1 font-mono">{formatWhen(pageData.activeJob.updatedAt)}</strong>
                            </div>
                        </div>
                    </div>
                ) : null}

                {/* Backup History Table */}
                <div className="bg-neutral-800 border border-neutral-700 rounded-lg overflow-hidden">
                    <div className="px-6 py-4 border-b border-neutral-700 bg-neutral-800/80">
                        <h2 className="text-lg font-bold text-neutral-100">Backup History</h2>
                    </div>
                    
                    <div className="flex flex-col">
                        {!backups.length ? (
                            <div className="p-8 text-center text-sm text-neutral-500">No backups were recorded yet.</div>
                        ) : null}
                        
                        {backups.map((entry, index) => (
                            <div key={entry.id} className={`p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors hover:bg-neutral-700/20 ${index !== backups.length - 1 ? 'border-b border-neutral-700/50' : ''}`}>
                                <div className="flex flex-col gap-2">
                                    <div className="flex items-center gap-3">
                                        <i className="bi bi-archive text-xl text-neutral-400"></i>
                                        <strong className="text-neutral-100 font-mono text-sm tracking-wide">
                                            {formatWhen(entry.createdAt)}
                                        </strong>
                                        <div className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide inline-block ${statusColorClass(entry.status)}`}>
                                            {entry.status || 'unknown'}
                                        </div>
                                    </div>
                                    <div className="text-sm text-neutral-400 flex items-center gap-2 pl-8">
                                        <span className="capitalize">{entry.trigger || 'manual'}</span> 
                                        <span className="text-neutral-600">•</span>
                                        <span className="font-mono">{formatBytes(entry.sizeBytes)}</span>
                                    </div>
                                    {entry.error ? (
                                        <div className="text-xs text-red-400 font-mono mt-1 pl-8 bg-red-900/10 p-2 rounded">
                                            <i className="bi bi-exclamation-triangle mr-1"></i> {entry.error}
                                        </div>
                                    ) : null}
                                </div>
                                
                                <div className="flex flex-wrap items-center gap-2 sm:justify-end shrink-0 pt-3 sm:pt-0 border-t border-neutral-700 sm:border-0 pl-8 sm:pl-0">
                                    {entry.webViewLink ? (
                                        <a href={entry.webViewLink} className="bg-transparent hover:bg-neutral-700 text-neutral-300 hover:text-white border border-neutral-600 hover:border-neutral-500 text-xs font-semibold py-1.5 px-4 rounded transition-colors flex items-center gap-2" target="_blank" rel="noreferrer">
                                            <i className="bi bi-link-45deg"></i> Open File
                                        </a>
                                    ) : null}
                                    {entry.folderLink ? (
                                        <a href={entry.folderLink} className="bg-neutral-700 hover:bg-neutral-600 text-white border border-neutral-600 hover:border-neutral-500 text-xs font-semibold py-1.5 px-4 rounded transition-colors flex items-center gap-2" target="_blank" rel="noreferrer">
                                            <i className="bi bi-folder2-open"></i> Folder
                                        </a>
                                    ) : null}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerBackupsPage;

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <ServerBackupsPage pageData={data} />
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}