import React from 'react';
import { createRoot } from 'react-dom/client';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const root = createRoot(document.getElementById('reactRoot'));

function resolveBrandImage() {
    return data.faviconUrl || '/assets/rocky.png';
}

function ChangeViewApp() {
    React.useEffect(() => {
        if (!data.applied) return;
        try {
            window.localStorage.clear();
        } catch (_) {}
        const timer = window.setTimeout(() => {
            window.location.replace('/');
        }, 150);
        return () => window.clearTimeout(timer);
    }, []);

    return (
        <div className="react-basic-page react-experimental-page">
            <div className="react-basic-shell react-experimental-shell">
                <header className="react-basic-topbar">
                    <div className="react-basic-brand">
                        <div className="react-basic-brand-mark">
                            <img src={resolveBrandImage()} alt={data.brandName || 'CPanel'} className="react-brand-image" />
                        </div>
                        <div>
                            <div className="react-basic-brand-title">{data.brandName || 'CPanel'}</div>
                            <div className="react-basic-brand-subtitle">Change renderer</div>
                        </div>
                    </div>

                    <div className="react-basic-actions">
                        <a className="react-top-action" href="/experimental-features" title="Experimental Features">
                            <i className="bi bi-sliders"></i>
                        </a>
                        <a className="react-top-action" href="/" title="Dashboard">
                            <i className="bi bi-grid-1x2"></i>
                        </a>
                    </div>
                </header>

                <main className="react-experimental-layout">
                    <div className="react-experimental-scroll">
                        {data.success ? <div className="react-account-flash is-success">{data.success}</div> : null}
                        {data.error ? <div className="react-account-flash is-danger">{data.error}</div> : null}

                        <div className="react-experimental-grid react-change-view-grid">
                            <section className="react-account-card">
                                <div className="react-account-section-title">Legacy EJS View</div>
                                <div className="react-account-muted">Stable production renderer. Full theme support and complete route coverage.</div>
                                <div className="react-experimental-stat-row">
                                    {data.currentViewMode === 'ejs' ? (
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
                                    {data.currentViewMode === 'react' ? (
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
            </div>
        </div>
    );
}

root.render(<ChangeViewApp />);
if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
    window.__CPANEL_REACT_BOOTED__();
}
