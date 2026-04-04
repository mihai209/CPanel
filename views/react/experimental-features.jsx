import React from 'react';
import { createRoot } from 'react-dom/client';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const root = createRoot(document.getElementById('reactRoot'));

function resolveBrandImage() {
    return data.faviconUrl || '/assets/rocky.png';
}

function resolveUserAvatar(user) {
    if (user && user.avatarProvider === 'url' && user.avatarUrl) {
        return user.avatarUrl;
    }
    if (user && user.gravatarHash) {
        return `https://www.gravatar.com/avatar/${user.gravatarHash}?d=retro&s=96`;
    }
    return resolveBrandImage();
}

function TopAction({ href, icon, title }) {
    return (
        <a className="react-top-action" href={href} title={title}>
            <i className={`bi ${icon}`}></i>
        </a>
    );
}

function ExperimentalFeaturesApp() {
    const user = data.user || {};
    const avatar = resolveUserAvatar(user);
    const brandImage = resolveBrandImage();
    const aiAvailable = Boolean(data.aiAdminEnabled && data.aiProviderReady);

    return (
        <div className="react-basic-page react-experimental-page">
            <div className="react-basic-shell react-experimental-shell">
                <header className="react-basic-topbar">
                    <div className="react-basic-brand">
                        <div className="react-basic-brand-mark">
                            <img src={brandImage} alt={data.brandName || 'CPanel'} className="react-brand-image" />
                        </div>
                        <div>
                            <div className="react-basic-brand-title">{data.brandName || 'CPanel'}</div>
                            <div className="react-basic-brand-subtitle">Experimental features</div>
                        </div>
                    </div>

                    <div className="react-basic-actions">
                        <TopAction href="/" icon="bi-grid-1x2" title="Dashboard" />
                        <TopAction href="/account" icon="bi-person" title="Account" />
                        <TopAction href="/experimental/change-view" icon="bi-sliders" title="Change View" />
                        <div className="react-basic-user">
                            <img src={avatar} alt={user.username || 'User'} className="react-basic-user-avatar" />
                            <span>{user.username ? `@${user.username}` : 'Unknown'}</span>
                        </div>
                    </div>
                </header>

                <main className="react-experimental-layout">
                    <div className="react-experimental-scroll">
                        {data.success ? <div className="react-account-flash is-success">{data.success}</div> : null}
                        {data.error ? <div className="react-account-flash is-danger">{data.error}</div> : null}

                        <div className="react-experimental-grid">
                            <section className="react-account-card">
                                <div className="react-account-section-title">React View Mode</div>
                                <div className="react-account-muted">Switch between the stable EJS renderer and the React beta renderer for migrated pages.</div>
                                <div className="react-experimental-stat-row">
                                    <span className={`react-account-badge ${data.currentViewMode === 'react' ? 'is-info' : 'is-muted'}`}>
                                        {data.currentViewMode === 'react' ? 'React Active' : 'EJS Active'}
                                    </span>
                                </div>
                                <div className="react-account-inline-actions">
                                    <a href="/experimental/change-view" className="react-account-button is-primary">Open Change View</a>
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
                                            <span>{data.aiAdminEnabled ? 'Enabled' : 'Disabled'}</span>
                                        </div>
                                        <div className="react-side-item-note">Global AI availability from admin settings.</div>
                                    </div>
                                    <div className="react-side-item">
                                        <div className="react-side-item-head">
                                            <strong>Provider state</strong>
                                            <span>{data.aiProviderReady ? 'Ready' : 'Not ready'}</span>
                                        </div>
                                        <div className="react-side-item-note">At least one enabled provider with an API key.</div>
                                    </div>
                                    <div className="react-side-item">
                                        <div className="react-side-item-head">
                                            <strong>Daily quota</strong>
                                            <span>{`${data.quotaUsed || 0}/${data.quotaLimit || 100}`}</span>
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
            </div>
        </div>
    );
}

root.render(<ExperimentalFeaturesApp />);
if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
    window.__CPANEL_REACT_BOOTED__();
}
