import React from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';

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
            className="react-ui-button is-ghost is-small"
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

    return (
        <ReactAppShell pageData={pageData} subtitle="API keys" pageClassName="react-api-page">
            <main className="react-surface-page">
                <section className="react-surface-header">
                    <div>
                        <p className="react-surface-eyebrow">Automation</p>
                        <h1>API Keys</h1>
                        <p className="react-surface-copy">Create and rotate per-server API credentials without leaving the React view. Existing POST flows remain unchanged.</p>
                    </div>
                </section>

                {(pageData.success || pageData.error) ? (
                    <div className={`react-inline-alert ${pageData.error ? 'is-danger' : 'is-success'}`}>{pageData.error || pageData.success}</div>
                ) : null}

                {pageData.freshToken && pageData.freshToken.token ? (
                    <section className="react-ui-panel">
                        <div className="react-panel-heading">New Token</div>
                        <div className="react-token-row">
                            <code>{pageData.freshToken.token}</code>
                            <CopyTokenButton value={pageData.freshToken.token} />
                        </div>
                        <p className="react-panel-copy">This is the only time the full token is shown.</p>
                    </section>
                ) : null}

                <section className="react-api-grid">
                    <div className="react-ui-panel">
                        <div className="react-panel-heading">Create API Key</div>
                        <form method="POST" action={actions.create} className="react-stack-form">
                            <label className="react-form-field">
                                <span>Description</span>
                                <input type="text" name="name" maxLength={120} required placeholder="CI deploy key" />
                            </label>
                            <label className="react-form-field">
                                <span>Expires at</span>
                                <input type="datetime-local" name="expiresAt" />
                            </label>
                            <div className="react-check-grid">
                                {permissionCatalog.map((permission) => (
                                    <label key={permission} className="react-check-tile">
                                        <input type="checkbox" name="permissions" value={permission} defaultChecked={permission === 'server.view'} />
                                        <span>{permission}</span>
                                    </label>
                                ))}
                            </div>
                            <button type="submit" className="react-ui-button is-primary" disabled={!canManage}>Create Key</button>
                        </form>
                    </div>

                    <div className="react-ui-panel">
                        <div className="react-panel-heading">API Keys</div>
                        <div className="react-list-body">
                            {!apiKeys.length ? <div className="react-empty-state">No API keys exist for this server yet.</div> : null}
                            {apiKeys.map((entry) => (
                                <div key={entry.id} className="react-list-row is-stacked-mobile">
                                    <div className="react-list-main">
                                        <div className={`react-pill-badge ${entry.active ? 'is-success' : 'is-danger'}`}>{entry.active ? 'Active' : 'Inactive'}</div>
                                        <strong>{entry.name}</strong>
                                        <span>{entry.keyPrefixMasked}</span>
                                        <small>{`Last used: ${formatDate(entry.lastUsedAt, 'Never')}`}</small>
                                    </div>
                                    <div className="react-row-actions">
                                        <form method="POST" action={`${actions.keyBase}/${entry.id}/rotate`}>
                                            <button type="submit" className="react-ui-button is-ghost is-small" disabled={!canManage || !entry.active}>Rotate</button>
                                        </form>
                                        <form method="POST" action={`${actions.keyBase}/${entry.id}/revoke`}>
                                            <button type="submit" className="react-ui-button is-danger is-small" disabled={!canManage || !entry.active}>Revoke</button>
                                        </form>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </section>
            </main>
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
