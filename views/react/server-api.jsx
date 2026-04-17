import React from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-api';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function formatDate(value, fallback = 'Never') {
    if (!value) return fallback;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? fallback : date.toLocaleString();
}

function CopyTokenButton({ value }) {
    const [copied, setCopied] = React.useState(false);
    if (!value) return null;
    return (
        <button
            type="button"
            className="bg-neutral-800 hover:bg-neutral-700 text-neutral-300 hover:text-white border border-neutral-700 font-semibold py-1.5 px-3 rounded text-sm transition-colors opacity-90 hover:opacity-100 flex items-center justify-center min-w-[70px]"
            onClick={async () => {
                try {
                    await navigator.clipboard.writeText(value);
                    setCopied(true);
                    window.setTimeout(() => setCopied(false), 1200);
                } catch {
                    setCopied(false);
                }
            }}
        >
            {copied ? 'Copied' : 'Copy'}
        </button>
    );
}

export function ServerApiPage({ pageData = data }) {
    const apiKeys = Array.isArray(pageData.apiKeys) ? pageData.apiKeys : [];
    const canManage = Boolean(pageData.permissions && pageData.permissions.canManageApiKeys);
    const permissionCatalog = Array.isArray(pageData.apiPermissionCatalog) ? pageData.apiPermissionCatalog : [];
    const actions = pageData.actions || {};

    const inputClass = "w-full bg-neutral-900 border border-neutral-700/50 rounded p-2.5 text-sm text-neutral-200 focus:ring-2 focus:ring-primary-500 focus:border-transparent outline-none transition-shadow";
    const labelClass = "block text-xs font-bold text-neutral-400 uppercase tracking-wide mb-1.5";

    return (
        <ReactAppShell pageData={pageData} subtitle="API keys">
            <PageContentBlock title="API Keys" description="Create and rotate per-server API credentials without leaving the React view. Existing POST flows remain unchanged." eyebrow="Automation">
                
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

                {pageData.freshToken && pageData.freshToken.token ? (
                    <section className="bg-neutral-800 border-2 border-primary-600/50 rounded-lg p-6 mb-6">
                        <h2 className="text-lg font-bold text-white mb-2">New Token Created</h2>
                        <p className="text-sm text-primary-300 mb-4 font-semibold">This is the only time the full token is shown. Please copy it now.</p>
                        <div className="bg-neutral-900 border border-neutral-700 flex flex-col sm:flex-row items-center justify-between rounded p-4 gap-4">
                            <code className="text-primary-400 font-mono text-sm break-all">{pageData.freshToken.token}</code>
                            <div className="shrink-0 w-full sm:w-auto flex justify-end">
                                <CopyTokenButton value={pageData.freshToken.token} />
                            </div>
                        </div>
                    </section>
                ) : null}

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                    
                    {/* Create Keys Form */}
                    <div className="lg:col-span-4 flex flex-col gap-6">
                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6">
                            <h2 className="text-lg font-bold text-neutral-100 mb-6">Create API Key</h2>
                            <form method="POST" action={actions.create} className="flex flex-col gap-5">
                                <label>
                                    <span className={labelClass}>Description</span>
                                    <input type="text" name="name" maxLength={120} required placeholder="CI deploy key" className={inputClass} />
                                </label>
                                <label>
                                    <span className={labelClass}>Expires at</span>
                                    <input type="datetime-local" name="expiresAt" className={`${inputClass} text-neutral-400`} />
                                </label>
                                
                                <div className="mt-2">
                                    <span className={labelClass}>Permissions</span>
                                    <div className="bg-neutral-900/50 border border-neutral-700/50 rounded-lg p-4 flex flex-col gap-3 max-h-[300px] overflow-y-auto mt-2">
                                        {permissionCatalog.map((permission) => (
                                            <label key={permission} className="flex items-start gap-3 cursor-pointer group">
                                                <input 
                                                    type="checkbox" 
                                                    name="permissions" 
                                                    value={permission} 
                                                    defaultChecked={permission === 'server.view'} 
                                                    className="w-4 h-4 mt-0.5 rounded border-neutral-600 bg-neutral-900 text-primary-600 focus:ring-primary-600 focus:ring-offset-neutral-800"
                                                />
                                                <span className="text-sm text-neutral-300 font-mono group-hover:text-white transition-colors">{permission}</span>
                                            </label>
                                        ))}
                                    </div>
                                </div>

                                <div className="mt-2 flex justify-end">
                                    <button type="submit" className="w-full bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50" disabled={!canManage}>
                                        Create Key
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>

                    {/* API Keys List */}
                    <div className="lg:col-span-8 flex flex-col gap-6">
                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg overflow-hidden">
                            <div className="px-6 py-4 border-b border-neutral-700 bg-neutral-800/80">
                                <h2 className="text-lg font-bold text-neutral-100">Active API Keys</h2>
                            </div>
                            
                            <div className="flex flex-col">
                                {!apiKeys.length ? (
                                    <div className="p-8 text-center text-sm text-neutral-500">No API keys exist for this server yet.</div>
                                ) : null}
                                
                                {apiKeys.map((entry, index) => (
                                    <div key={entry.id} className={`p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${index !== apiKeys.length - 1 ? 'border-b border-neutral-700/50' : ''}`}>
                                        <div className="flex flex-col gap-1.5">
                                            <div className="flex flex-wrap items-center gap-3">
                                                <strong className="text-neutral-100">{entry.name}</strong>
                                                <div className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide ${entry.active ? 'bg-green-600/20 text-green-400 border border-green-600/30' : 'bg-red-600/20 text-red-400 border border-red-600/30'}`}>
                                                    {entry.active ? 'Active' : 'Inactive'}
                                                </div>
                                            </div>
                                            
                                            <div className="flex items-center gap-2 mt-1">
                                                <span className="text-sm font-mono text-neutral-400 bg-neutral-900 px-2 py-0.5 rounded">{entry.keyPrefixMasked}</span>
                                            </div>
                                            
                                            <small className="text-xs text-neutral-500 mt-1 flex items-center gap-1.5">
                                                <i className="bi bi-clock-history"></i>
                                                Last used: {formatDate(entry.lastUsedAt, 'Never')}
                                            </small>
                                        </div>
                                        
                                        <div className="flex flex-wrap items-center gap-2 sm:justify-end shrink-0 pt-2 sm:pt-0 mt-3 sm:mt-0 border-t border-neutral-700 sm:border-0">
                                            <form method="POST" action={`${actions.keyBase}/${entry.id}/rotate`}>
                                                <button type="submit" className="bg-transparent hover:bg-neutral-700 text-neutral-300 hover:text-white border border-neutral-600 hover:border-neutral-500 text-xs font-semibold py-1.5 px-3 rounded transition-colors disabled:opacity-50" disabled={!canManage || !entry.active}>
                                                    Rotate
                                                </button>
                                            </form>
                                            <form method="POST" action={`${actions.keyBase}/${entry.id}/revoke`}>
                                                <button type="submit" className="bg-red-600/20 hover:bg-red-600 text-red-400 hover:text-white border border-red-600/30 hover:border-red-600 text-xs font-semibold py-1.5 px-3 rounded transition-colors disabled:opacity-50" disabled={!canManage || !entry.active}>
                                                    Revoke
                                                </button>
                                            </form>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>

                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerApiPage;

if (root) {
    root.render(<ServerApiPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
