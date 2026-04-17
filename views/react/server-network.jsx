import React from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-network';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ServerNetworkPage({ pageData = data }) {
    const allocations = Array.isArray(pageData.allocations) ? pageData.allocations : [];
    const availableAllocations = Array.isArray(pageData.availableAllocations) ? pageData.availableAllocations : [];
    const summary = pageData.networkSummary || {};
    const canManage = Boolean(pageData.permissions && pageData.permissions.canManageNetwork);
    const actions = pageData.actions || {};

    const inputClass = "w-full bg-neutral-900 border border-neutral-700/50 rounded p-2.5 text-sm text-neutral-200 focus:ring-2 focus:ring-primary-500 focus:border-transparent outline-none transition-shadow";
    const labelClass = "block text-xs font-bold text-neutral-400 uppercase tracking-wide mb-1.5";

    return (
        <ReactAppShell pageData={pageData} subtitle="Network">
            <PageContentBlock title="Network Settings" description="Review assigned allocations, switch the primary binding, and assign additional ports." eyebrow="Routing">
                
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

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start mb-6">
                    
                    {/* Allocation Summary Card */}
                    <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6 lg:col-span-1">
                        <h2 className="text-lg font-bold text-neutral-100 mb-4">Allocation Summary</h2>
                        <div className="flex flex-col gap-4">
                            <div className="flex justify-between items-center border-b border-neutral-700/50 pb-3">
                                <span className="text-sm font-semibold text-neutral-400">Total assigned</span>
                                <strong className="text-neutral-200 font-mono">{allocations.length}</strong>
                            </div>
                            <div className="flex justify-between items-center border-b border-neutral-700/50 pb-3">
                                <span className="text-sm font-semibold text-neutral-400">Token inventory</span>
                                <strong className="text-neutral-200 font-mono">{summary.allocationTokens || 0}</strong>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-sm font-semibold text-neutral-400">Assignable left</span>
                                <strong className="text-neutral-200 font-mono">{summary.remainingAssignable || 0}</strong>
                            </div>
                        </div>
                        {summary.inventoryAssignBlockedReason && (
                            <div className="mt-6 bg-yellow-900/20 border border-yellow-500/30 text-yellow-200 p-3 rounded text-sm flex items-start gap-2">
                                <i className="bi bi-exclamation-circle text-yellow-500 mt-0.5"></i>
                                {summary.inventoryAssignBlockedReason}
                            </div>
                        )}
                    </div>

                    {/* Assigner */}
                    {canManage && availableAllocations.length ? (
                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6 lg:col-span-2">
                            <h2 className="text-lg font-bold text-neutral-100 mb-6">Assign Allocation</h2>
                            <form method="POST" action={actions.assign} className="flex flex-col gap-5">
                                <label>
                                    <span className={labelClass}>Available Port</span>
                                    <div className="relative">
                                        <select name="allocationId" defaultValue={availableAllocations[0].id} className={`${inputClass} font-mono appearance-none`}>
                                            {availableAllocations.map((entry) => (
                                                <option key={entry.id} value={entry.id}>{`${entry.ip}:${entry.port}`}</option>
                                            ))}
                                        </select>
                                        <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-4 text-neutral-400">
                                            <i className="bi bi-chevron-down"></i>
                                        </div>
                                    </div>
                                    <span className="block text-xs text-neutral-500 mt-2">These are unassigned ports mapped to your node that are currently reserved exclusively for you.</span>
                                </label>
                                <div className="mt-2 flex justify-end">
                                    <button type="submit" className="bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm">Assign Port</button>
                                </div>
                            </form>
                        </div>
                    ) : (canManage && !availableAllocations.length) ? (
                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6 lg:col-span-2 flex flex-col justify-center items-center text-center">
                            <i className="bi bi-hdd-network text-4xl text-neutral-600 mb-3"></i>
                            <h2 className="text-lg font-bold text-neutral-100 mb-1">No Ports Available</h2>
                            <p className="text-sm text-neutral-400">You do not have any free allocations available to assign.</p>
                        </div>
                    ) : null}

                </div>

                {/* Listing */}
                <div className="bg-neutral-800 border border-neutral-700 rounded-lg overflow-hidden">
                    <div className="px-6 py-4 border-b border-neutral-700 bg-neutral-800/80">
                        <h2 className="text-lg font-bold text-neutral-100">Assigned Allocations</h2>
                    </div>
                    
                    <div className="flex flex-col">
                        {!allocations.length ? (
                            <div className="p-8 text-center text-sm text-neutral-500">No allocations are assigned to this server.</div>
                        ) : null}
                        
                        {allocations.map((entry, index) => (
                            <div key={entry.id} className={`p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${index !== allocations.length - 1 ? 'border-b border-neutral-700/50' : ''}`}>
                                <div className="flex flex-col gap-2">
                                    <div className="flex items-center gap-3">
                                        <strong className="text-neutral-100 font-mono text-lg tracking-wide bg-neutral-900 border border-neutral-700 px-3 py-1 rounded">
                                            {`${entry.ip}:${entry.port}`}
                                        </strong>
                                        <div className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wide inline-block ${entry.isPrimary ? 'bg-primary-600/20 text-primary-400 border border-primary-600/30' : 'bg-neutral-700 text-neutral-400 border border-neutral-600'}`}>
                                            {entry.isPrimary ? 'Primary' : 'Secondary'}
                                        </div>
                                    </div>
                                    <span className="text-sm text-neutral-500 itlaic">
                                        {entry.notes || 'No notes configured.'}
                                    </span>
                                </div>
                                
                                {canManage ? (
                                    <div className="flex flex-wrap items-center gap-2 sm:justify-end shrink-0 pt-3 sm:pt-0 border-t border-neutral-700 sm:border-0 mt-2 sm:mt-0">
                                        {!entry.isPrimary ? (
                                            <form method="POST" action={`${actions.primaryBase}/${entry.id}/primary`}>
                                                <button type="submit" className="bg-transparent hover:bg-neutral-700 text-neutral-300 hover:text-white border border-neutral-600 hover:border-neutral-500 text-xs font-semibold py-2 px-4 rounded transition-colors disabled:opacity-50">
                                                    Make Primary
                                                </button>
                                            </form>
                                        ) : null}
                                        {!entry.isPrimary ? (
                                            <form method="POST" action={`${actions.removeBase}/${entry.id}/delete`}>
                                                <button type="submit" className="bg-red-600/20 hover:bg-red-600 text-red-400 hover:text-white border border-red-600/30 hover:border-red-600 text-xs font-semibold py-2 px-4 rounded transition-colors disabled:opacity-50">
                                                    Remove
                                                </button>
                                            </form>
                                        ) : null}
                                    </div>
                                ) : null}
                            </div>
                        ))}
                    </div>
                </div>

            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerNetworkPage;

if (root) {
    root.render(<ServerNetworkPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
