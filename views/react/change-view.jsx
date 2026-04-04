import React from 'react';
import { createRoot } from 'react-dom/client';
import { ReactRoutes } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';

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
        <ReactAppShell pageData={pageData} subtitle="Change renderer" pageClassName="react-experimental-page" shellClassName="react-experimental-shell">
            <main className="react-experimental-layout">
                    <div className="react-experimental-scroll">
                        {pageData.success ? <div className="react-account-flash is-success">{pageData.success}</div> : null}
                        {pageData.error ? <div className="react-account-flash is-danger">{pageData.error}</div> : null}

                        <div className="react-experimental-grid react-change-view-grid">
                            <section className="react-account-card">
                                <div className="react-account-section-title">Legacy EJS View</div>
                                <div className="react-account-muted">Stable production renderer. Full theme support and complete route coverage.</div>
                                <div className="react-experimental-stat-row">
                                    {pageData.currentViewMode === 'ejs' ? (
                                        <span className="react-account-badge is-success">Active</span>
                                    ) : (
                                        <span className="react-account-badge is-muted">Available</span>
                                    )}
                                </div>
                                <form method="POST" action="/experimental/change-view" className="react-account-form">
                                    <input type="hidden" name="viewMode" value="ejs" />
                                    <div className="react-account-form-actions">
                                        <button type="submit" className="react-account-button is-primary">Use EJS View</button>
                                    </div>
                                </form>
                            </section>

                            <section className="react-account-card">
                                <div className="react-account-section-title">React Beta View</div>
                                <div className="react-account-muted">Dark fixed renderer for migrated pages. Faster iteration, partial route coverage, no custom themes.</div>
                                <div className="react-experimental-stat-row">
                                    {pageData.currentViewMode === 'react' ? (
                                        <span className="react-account-badge is-info">Active</span>
                                    ) : (
                                        <span className="react-account-badge is-muted">Available</span>
                                    )}
                                </div>
                                <form method="POST" action="/experimental/change-view" className="react-account-form">
                                    <input type="hidden" name="viewMode" value="react" />
                                    <div className="react-account-form-actions">
                                        <button type="submit" className="react-account-button is-primary">Use React Beta</button>
                                    </div>
                                </form>
                            </section>

                            <section className="react-account-card react-experimental-wide">
                                <div className="react-account-section-title">Apply Behavior</div>
                                <div className="react-account-muted">
                                    Switching renderer clears localStorage and redirects back to the main dashboard. This avoids stale UI state crossing between EJS and React.
                                </div>
                            </section>
                        </div>
                    </div>
            </main>
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
