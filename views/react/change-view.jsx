import React from 'react';
import { createRoot } from 'react-dom/client';
import { ReactRoutes } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'change-view';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ChangeViewPage({ pageData = data }) {
    React.useEffect(() => {
        if (!pageData.applied) return;
        try {
            window.localStorage.clear();
        } catch (_) {}
        const timer = window.setTimeout(() => {
            window.location.replace(ReactRoutes.dashboard);
        }, 150);
        return () => window.clearTimeout(timer);
    }, []);

    return (
        <ReactAppShell pageData={pageData} subtitle="Change renderer">
            <PageContentBlock title="Renderer Mode">
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

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <section className="bg-neutral-800 border border-neutral-700 rounded-lg p-6 flex flex-col hover:border-neutral-500 transition-colors">
                        <div className="flex justify-between items-start mb-4">
                            <div>
                                <h2 className="text-lg font-bold text-neutral-100">Legacy EJS View</h2>
                                <p className="text-sm text-neutral-400 mt-1">Stable production renderer. Full theme support and complete route coverage.</p>
                            </div>
                            <span className={`px-2 py-1 rounded text-xs font-semibold uppercase tracking-wide ${pageData.currentViewMode === 'ejs' ? 'bg-green-600 text-white' : 'bg-neutral-700 text-neutral-400'}`}>
                                {pageData.currentViewMode === 'ejs' ? 'Active' : 'Available'}
                            </span>
                        </div>
                        <div className="mt-auto pt-4 border-t border-neutral-700">
                            <form method="POST" action="/experimental/change-view">
                                <input type="hidden" name="viewMode" value="ejs" />
                                <button type="submit" className="w-full bg-neutral-700 hover:bg-neutral-600 text-neutral-200 font-semibold py-2 px-4 rounded transition-colors text-sm">
                                    Use EJS View
                                </button>
                            </form>
                        </div>
                    </section>

                    <section className="bg-neutral-800 border border-neutral-700 rounded-lg p-6 flex flex-col hover:border-neutral-500 transition-colors">
                        <div className="flex justify-between items-start mb-4">
                            <div>
                                <h2 className="text-lg font-bold text-neutral-100">React Beta View</h2>
                                <p className="text-sm text-neutral-400 mt-1">Dark fixed renderer for migrated pages. Faster iteration, partial route coverage, no custom themes.</p>
                            </div>
                            <span className={`px-2 py-1 rounded text-xs font-semibold uppercase tracking-wide ${pageData.currentViewMode === 'react' ? 'bg-primary-600 text-white' : 'bg-neutral-700 text-neutral-400'}`}>
                                {pageData.currentViewMode === 'react' ? 'Active' : 'Available'}
                            </span>
                        </div>
                        <div className="mt-auto pt-4 border-t border-neutral-700">
                            <form method="POST" action="/experimental/change-view">
                                <input type="hidden" name="viewMode" value="react" />
                                <button type="submit" className="w-full bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-4 rounded transition-colors text-sm shadow-sm opacity-90 shadow-primary-900/50">
                                    Use React Beta
                                </button>
                            </form>
                        </div>
                    </section>

                    <section className="bg-neutral-800 border border-neutral-700 rounded-lg p-6 md:col-span-2">
                        <h2 className="text-lg font-bold text-neutral-100 mb-2">Apply Behavior</h2>
                        <p className="text-sm text-neutral-400">
                            Switching renderer clears localStorage and redirects back to the main dashboard. This avoids stale UI state crossing between EJS and React.
                        </p>
                    </section>
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ChangeViewPage;

if (root) {
    root.render(<ChangeViewPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
