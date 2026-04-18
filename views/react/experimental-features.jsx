import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Link } from 'react-router-dom';
import { ReactRoutes } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'experimental-features';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function MetricItem({ title, value, note, active }) {
    return (
        <div className="bg-neutral-900/50 border border-neutral-700/50 rounded-lg p-4">
            <div className="flex justify-between items-center mb-1">
                <span className="text-xs font-bold text-neutral-500 uppercase tracking-wide">{title}</span>
                <strong className={`text-sm ${active ? 'text-primary-400' : 'text-neutral-300'}`}>{value}</strong>
            </div>
            <div className="text-xs text-neutral-500">{note}</div>
        </div>
    );
}

export function ExperimentalFeaturesPage({ pageData = data }) {
    const user = pageData.user || {};
    const aiAvailable = Boolean(pageData.aiAdminEnabled && pageData.aiProviderReady);

    return (
        <ReactAppShell pageData={pageData} subtitle="Outdated features">
            <PageContentBlock title="Outdated Features">
                <div className="bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3">
                    <i className="bi bi-info-circle text-xl"></i>
                    <div>
                        <strong className="block">Notice</strong>
                        <p className="text-sm">Sorry but features that were added here will still be working but wont be updated anymore</p>
                    </div>
                </div>
                {pageData.success && (
                    <div className="bg-green-600/20 border border-green-600/50 text-green-100 p-4 rounded-lg mb-6 shadow-sm">
                        {pageData.success}
                    </div>
                )}
                {pageData.error && (
                    <div className="bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm">
                        {pageData.error}
                    </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <section className="bg-neutral-800 border border-neutral-700 rounded-lg p-6 flex flex-col hover:border-neutral-500 transition-colors">
                        <div className="flex justify-between items-start mb-4">
                            <div>
                                <h2 className="text-lg font-bold text-neutral-100">React View Mode</h2>
                                <p className="text-sm text-neutral-400 mt-1">Switch between the stable EJS renderer and the React beta renderer for migrated pages.</p>
                            </div>
                            <span className={`px-2 py-1 rounded text-xs font-semibold uppercase tracking-wide shrink-0 ml-4 ${pageData.currentViewMode === 'react' ? 'bg-primary-600 text-white' : 'bg-neutral-700 text-neutral-400'}`}>
                                {pageData.currentViewMode === 'react' ? 'React Active' : 'EJS Active'}
                            </span>
                        </div>
                        <div className="mt-auto pt-4">
                            <Link to={ReactRoutes.changeView} className="inline-block bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm">
                                Open Change View
                            </Link>
                        </div>
                    </section>

                    <section className="bg-neutral-800 border border-neutral-700 rounded-lg p-6 flex flex-col hover:border-neutral-500 transition-colors">
                        <div className="mb-4">
                            <h2 className="text-lg font-bold text-neutral-100">AI Agents</h2>
                            <p className="text-sm text-neutral-400 mt-1">User-side AI is controlled both by admin configuration and your own opt-in setting.</p>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-6">
                            <MetricItem title="Admin switch" value={pageData.aiAdminEnabled ? 'Enabled' : 'Disabled'} active={pageData.aiAdminEnabled} note="Global AI availability from admin settings." />
                            <MetricItem title="Provider state" value={pageData.aiProviderReady ? 'Ready' : 'Not ready'} active={pageData.aiProviderReady} note="At least one enabled provider with an API key." />
                            <div className="sm:col-span-2">
                                <MetricItem title="Daily quota" value={`${pageData.quotaUsed || 0}/${pageData.quotaLimit || 100}`} active={true} note="Usage resets daily." />
                            </div>
                        </div>
                        <form method="POST" action="/instable/outdated/ai" className="mt-auto border-t border-neutral-700 pt-5">
                            <label className={`flex items-start gap-3 cursor-pointer ${!aiAvailable ? 'opacity-50' : ''}`}>
                                <input
                                    type="checkbox"
                                    name="enabled"
                                    value="true"
                                    className="w-5 h-5 mt-0.5 rounded border-neutral-600 bg-neutral-900 text-primary-600 focus:ring-primary-600 focus:ring-offset-neutral-800"
                                    defaultChecked={Boolean(user.experimentalAiEnabled)}
                                    disabled={!aiAvailable}
                                />
                                <div>
                                    <strong className="block text-sm font-bold text-neutral-200">Enable experimental AI for this account</strong>
                                    <span className="block text-sm text-neutral-400 mt-0.5">
                                        {aiAvailable ? 'You can opt in safely from here.' : 'Admin must enable AI and configure at least one provider first.'}
                                    </span>
                                </div>
                            </label>
                            <div className="mt-5">
                                <button type="submit" className="bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50 disabled:cursor-not-allowed" disabled={!aiAvailable}>
                                    Save Experimental AI
                                </button>
                            </div>
                        </form>
                    </section>

                    <section className="bg-neutral-800 border border-neutral-700 rounded-lg p-6 lg:col-span-2">
                        <h2 className="text-lg font-bold text-neutral-100 mb-4">Current Beta Notes</h2>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div className="bg-primary-900/20 border border-primary-500/30 rounded p-4">
                                <div className="text-xs font-bold text-primary-400 uppercase tracking-wide mb-1 flex justify-between">
                                    Dark fixed renderer <span>React</span>
                                </div>
                                <p className="text-sm text-primary-200/70 mt-2">React beta ignores custom themes and uses a fixed dark surface.</p>
                            </div>
                            <div className="bg-yellow-900/20 border border-yellow-500/30 rounded p-4">
                                <div className="text-xs font-bold text-yellow-400 uppercase tracking-wide mb-1 flex justify-between">
                                    Partial route coverage <span>Migrating</span>
                                </div>
                                <p className="text-sm text-yellow-200/70 mt-2">Only migrated pages use React. Everything else falls back to EJS.</p>
                            </div>
                            <div className="bg-neutral-900/50 border border-neutral-700 rounded p-4">
                                <div className="text-xs font-bold text-neutral-400 uppercase tracking-wide mb-1 flex justify-between">
                                    Storage reset on switch <span>Local only</span>
                                </div>
                                <p className="text-sm text-neutral-400 mt-2">Changing the renderer clears localStorage to avoid stale client state.</p>
                            </div>
                        </div>
                    </section>
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ExperimentalFeaturesPage;

if (root) {
    root.render(
        <BrowserRouter>
            <ExperimentalFeaturesPage pageData={data} />
        </BrowserRouter>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
