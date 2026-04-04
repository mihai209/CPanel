import React from 'react';
import { createRoot } from 'react-dom/client';
import { Link } from 'react-router-dom';
import { ReactRoutes } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'experimental-features';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ExperimentalFeaturesPage({ pageData = data }) {
    const user = pageData.user || {};
    const aiAvailable = Boolean(pageData.aiAdminEnabled && pageData.aiProviderReady);

    return (
        <ReactAppShell pageData={pageData} subtitle="Experimental features" pageClassName="react-experimental-page" shellClassName="react-experimental-shell">
            <main className="react-experimental-layout">
                    <div className="react-experimental-scroll">
                        {pageData.success ? <div className="react-account-flash is-success">{pageData.success}</div> : null}
                        {pageData.error ? <div className="react-account-flash is-danger">{pageData.error}</div> : null}

                        <div className="react-experimental-grid">
                            <section className="react-account-card">
                                <div className="react-account-section-title">React View Mode</div>
                                <div className="react-account-muted">Switch between the stable EJS renderer and the React beta renderer for migrated pages.</div>
                                <div className="react-experimental-stat-row">
                                    <span className={`react-account-badge ${pageData.currentViewMode === 'react' ? 'is-info' : 'is-muted'}`}>
                                        {pageData.currentViewMode === 'react' ? 'React Active' : 'EJS Active'}
                                    </span>
                                </div>
                                <div className="react-account-inline-actions">
                                    <Link to={ReactRoutes.changeView} className="react-account-button is-primary">Open Change View</Link>
                                </div>
                            </section>

                            <section className="react-account-card">
                                <div className="react-account-section-title">AI Agents</div>
                                <div className="react-account-muted">
                                    User-side AI is controlled both by admin configuration and your own opt-in setting.
                                </div>
                                <div className="react-experimental-stat-list">
                                    <div className="react-side-item">
                                        <div className="react-side-item-head">
                                            <strong>Admin switch</strong>
                                            <span>{pageData.aiAdminEnabled ? 'Enabled' : 'Disabled'}</span>
                                        </div>
                                        <div className="react-side-item-note">Global AI availability from admin settings.</div>
                                    </div>
                                    <div className="react-side-item">
                                        <div className="react-side-item-head">
                                            <strong>Provider state</strong>
                                            <span>{pageData.aiProviderReady ? 'Ready' : 'Not ready'}</span>
                                        </div>
                                        <div className="react-side-item-note">At least one enabled provider with an API key.</div>
                                    </div>
                                    <div className="react-side-item">
                                        <div className="react-side-item-head">
                                            <strong>Daily quota</strong>
                                            <span>{`${pageData.quotaUsed || 0}/${pageData.quotaLimit || 100}`}</span>
                                        </div>
                                        <div className="react-side-item-note">Usage resets daily.</div>
                                    </div>
                                </div>
                                <form method="POST" action="/experimental-features/ai" className="react-account-form">
                                    <label className="react-experimental-toggle">
                                        <input
                                            type="checkbox"
                                            name="enabled"
                                            value="true"
                                            defaultChecked={Boolean(user.experimentalAiEnabled)}
                                            disabled={!aiAvailable}
                                        />
                                        <div>
                                            <strong>Enable experimental AI for this account</strong>
                                            <span>{aiAvailable ? 'You can opt in safely from here.' : 'Admin must enable AI and configure at least one provider first.'}</span>
                                        </div>
                                    </label>
                                    <div className="react-account-form-actions">
                                        <button type="submit" className="react-account-button is-primary" disabled={!aiAvailable}>
                                            Save Experimental AI
                                        </button>
                                    </div>
                                </form>
                            </section>

                            <section className="react-account-card react-experimental-wide">
                                <div className="react-account-section-title">Current Beta Notes</div>
                                <div className="react-experimental-note-grid">
                                    <div className="react-side-item is-info">
                                        <div className="react-side-item-head">
                                            <strong>Dark fixed renderer</strong>
                                            <span>React</span>
                                        </div>
                                        <div className="react-side-item-note">React beta ignores custom themes and uses a fixed dark surface.</div>
                                    </div>
                                    <div className="react-side-item is-warning">
                                        <div className="react-side-item-head">
                                            <strong>Partial route coverage</strong>
                                            <span>Migrating</span>
                                        </div>
                                        <div className="react-side-item-note">Only migrated pages use React. Everything else falls back to EJS.</div>
                                    </div>
                                    <div className="react-side-item">
                                        <div className="react-side-item-head">
                                            <strong>Storage reset on switch</strong>
                                            <span>Local only</span>
                                        </div>
                                        <div className="react-side-item-note">Changing the renderer clears localStorage to avoid stale client state.</div>
                                    </div>
                                </div>
                            </section>
                        </div>
                    </div>
            </main>
        </ReactAppShell>
    );
}

export default ExperimentalFeaturesPage;

if (root) {
    root.render(<ExperimentalFeaturesPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
