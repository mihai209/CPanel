import React from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';

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

export function ServerBackupsPage({ pageData = data }) {
    const server = pageData.server || {};
    const backups = Array.isArray(pageData.backups) ? pageData.backups : [];
    const driveState = pageData.googleDriveState || {};
    const permissions = pageData.permissions || {};
    const policy = pageData.backupPolicy || {};
    const actions = pageData.actions || {};

    return (
        <ReactAppShell pageData={pageData} subtitle="Backups" pageClassName="react-backups-page">
            <main className="react-surface-page">
                <section className="react-surface-header">
                    <div>
                        <p className="react-surface-eyebrow">Recovery</p>
                        <h1>Backups</h1>
                        <p className="react-surface-copy">Review backup history, connect Google Drive for storage, and trigger fresh snapshots from the same backend flow used by EJS.</p>
                    </div>
                    <div className="react-surface-actions">
                        {permissions.canManageBackups ? (
                            <form method="POST" action={actions.run}>
                                <button type="submit" className="react-ui-button is-primary">Create Backup</button>
                            </form>
                        ) : null}
                    </div>
                </section>

                {(pageData.success || pageData.error) ? (
                    <div className={`react-inline-alert ${pageData.error ? 'is-danger' : 'is-success'}`}>{pageData.error || pageData.success}</div>
                ) : null}

                <section className="react-backups-grid">
                    <div className="react-ui-panel">
                        <div className="react-panel-heading">Drive Integration</div>
                        <div className="react-stat-list">
                            <div className="react-stat-row"><span>Server</span><strong>{server.name || 'Server'}</strong></div>
                            <div className="react-stat-row"><span>Drive Ready</span><strong>{driveState.ready ? 'Ready' : 'Needs setup'}</strong></div>
                            <div className="react-stat-row"><span>Last Run</span><strong>{formatWhen(policy.lastRunAt)}</strong></div>
                        </div>
                        <p className="react-panel-copy">{driveState.statusText || 'Google Drive state is unavailable.'}</p>
                        {driveState.canConnect ? (
                            <a href={actions.connectGoogle || driveState.connectUrl} className="react-ui-button is-ghost">Connect Google Drive</a>
                        ) : null}
                    </div>

                    <div className="react-ui-panel">
                        <div className="react-panel-heading">Policy</div>
                        <form method="POST" action={actions.savePolicy} className="react-stack-form">
                            <label className="react-form-field">
                                <span>Enable scheduled backups</span>
                                <input type="checkbox" name="enabled" defaultChecked={Boolean(policy.autoEnabled)} />
                            </label>
                            <label className="react-form-field">
                                <span>Interval in minutes</span>
                                <input type="number" name="intervalMinutes" min="5" max="10080" defaultValue={policy.intervalMinutes || 360} />
                            </label>
                            <button type="submit" className="react-ui-button is-primary" disabled={!permissions.canManageBackupPolicy}>Save Policy</button>
                        </form>
                    </div>
                </section>

                {pageData.activeJob ? (
                    <section className="react-ui-panel">
                        <div className="react-panel-heading">Active Job</div>
                        <div className="react-stat-list">
                            <div className="react-stat-row"><span>Status</span><strong>{pageData.activeJob.status}</strong></div>
                            <div className="react-stat-row"><span>Type</span><strong>{pageData.activeJob.type}</strong></div>
                            <div className="react-stat-row"><span>Updated</span><strong>{formatWhen(pageData.activeJob.updatedAt)}</strong></div>
                        </div>
                    </section>
                ) : null}

                <section className="react-ui-panel">
                    <div className="react-panel-heading">Backup History</div>
                    <div className="react-list-body">
                        {!backups.length ? <div className="react-empty-state">No backups were recorded yet.</div> : null}
                        {backups.map((entry) => (
                            <div key={entry.id} className="react-list-row is-stacked-mobile">
                                <div className="react-list-main">
                                    <div className={`react-pill-badge is-${statusTone(entry.status)}`}>{entry.status || 'unknown'}</div>
                                    <strong>{formatWhen(entry.createdAt)}</strong>
                                    <span>{entry.trigger || 'manual'} · {formatBytes(entry.sizeBytes)}</span>
                                    {entry.error ? <small>{entry.error}</small> : null}
                                </div>
                                <div className="react-row-actions">
                                    {entry.webViewLink ? <a href={entry.webViewLink} className="react-ui-button is-ghost is-small" target="_blank" rel="noreferrer">Open File</a> : null}
                                    {entry.folderLink ? <a href={entry.folderLink} className="react-ui-button is-ghost is-small" target="_blank" rel="noreferrer">Folder</a> : null}
                                </div>
                            </div>
                        ))}
                    </div>
                </section>
            </main>
        </ReactAppShell>
    );
}

export default ServerBackupsPage;

if (root) {
    root.render(<ServerBackupsPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
