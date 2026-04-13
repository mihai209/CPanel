import React from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-files';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function normalizePath(value) {
    const raw = String(value || '/').trim().replace(/\\/g, '/');
    if (!raw || raw === '/') return '/';
    const normalized = raw.startsWith('/') ? raw : `/${raw}`;
    return normalized.replace(/\/+/g, '/').replace(/\/$/, '') || '/';
}

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

function formatDate(value) {
    if (!value) return '-';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString();
}

function buildSegments(pathname) {
    const normalized = normalizePath(pathname);
    if (normalized === '/') return [{ label: 'home', path: '/' }];
    const parts = normalized.split('/').filter(Boolean);
    const segments = [{ label: 'home', path: '/' }];
    let current = '';
    parts.forEach((part) => {
        current += `/${part}`;
        segments.push({ label: part, path: current });
    });
    return segments;
}

export function ServerFilesPage({ pageData = data }) {
    const manager = pageData.fileManager || {};
    const permissions = pageData.permissions || {};
    const [currentPath, setCurrentPath] = React.useState(() => normalizePath(pageData.initialPath || '/'));
    const [entries, setEntries] = React.useState([]);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState(pageData.error || '');
    const [menuPath, setMenuPath] = React.useState('');

    React.useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError('');
        fetch(`${manager.fetchUrlBase}?path=${encodeURIComponent(currentPath)}`, {
            credentials: 'same-origin',
            headers: { Accept: 'application/json' }
        })
            .then(async (response) => {
                const payload = await response.json().catch(() => ({}));
                if (!response.ok || payload.error) {
                    throw new Error(payload.error || `Failed to load ${currentPath}`);
                }
                if (cancelled) return;
                const nextEntries = Array.isArray(payload.files) ? payload.files : [];
                nextEntries.sort((left, right) => {
                    if (left.isDirectory && !right.isDirectory) return -1;
                    if (!left.isDirectory && right.isDirectory) return 1;
                    return String(left.name || '').localeCompare(String(right.name || ''), undefined, { numeric: true, sensitivity: 'base' });
                });
                setEntries(nextEntries);
                setLoading(false);
            })
            .catch((requestError) => {
                if (cancelled) return;
                setEntries([]);
                setLoading(false);
                setError(requestError && requestError.message ? requestError.message : 'Failed to load files.');
            });
        return () => {
            cancelled = true;
        };
    }, [currentPath, manager.fetchUrlBase]);

    const breadcrumbs = buildSegments(currentPath);
    const activeServer = pageData.server || {};

    return (
        <ReactAppShell pageData={pageData} subtitle="File manager" pageClassName="react-files-page">
            <main className="react-surface-page">
                <section className="react-surface-header">
                    <div>
                        <p className="react-surface-eyebrow">Server Workspace</p>
                        <h1>File Manager</h1>
                        <p className="react-surface-copy">Browse container files, jump into the editor, or fall back to the legacy manager for advanced actions.</p>
                    </div>
                    <div className="react-surface-actions">
                        <a href={`${manager.legacyUrl}?legacy=1`} className="react-ui-button is-ghost">Open Legacy View</a>
                        {manager.webUploadEnabled ? (
                            <span className="react-inline-note">{`Uploads enabled up to ${manager.webUploadMaxMb} MB`}</span>
                        ) : null}
                    </div>
                </section>

                <section className="react-files-layout">
                    <aside className="react-ui-panel">
                        <div className="react-panel-heading">Storage Access</div>
                        <div className="react-stat-list">
                            <div className="react-stat-row"><span>Server</span><strong>{activeServer.name || 'Server'}</strong></div>
                            <div className="react-stat-row"><span>Status</span><strong>{activeServer.status || 'unknown'}</strong></div>
                            <div className="react-stat-row"><span>Writable</span><strong>{permissions.canWriteFiles && !permissions.filesWriteLocked ? 'Yes' : 'Read only'}</strong></div>
                            <div className="react-stat-row"><span>SFTP</span><strong>{pageData.sftpDetails && pageData.sftpDetails.available ? 'Available' : 'Unavailable'}</strong></div>
                        </div>
                        {permissions.filesWriteLocked ? (
                            <div className="react-inline-alert is-warning">File writes are locked by policy. Use editor and downloads in read-only mode.</div>
                        ) : null}
                    </aside>

                    <section className="react-ui-panel react-files-panel">
                        <div className="react-files-breadcrumbs">
                            {breadcrumbs.map((segment, index) => (
                                <button
                                    key={segment.path}
                                    type="button"
                                    className={`react-breadcrumb-button${index === breadcrumbs.length - 1 ? ' is-active' : ''}`}
                                    onClick={() => setCurrentPath(segment.path)}
                                >
                                    {segment.label}
                                </button>
                            ))}
                        </div>

                        {error ? <div className="react-inline-alert is-danger">{error}</div> : null}

                        <div className="react-list-header">
                            <div>Name</div>
                            <div>Modified</div>
                            <div>Size</div>
                            <div>Actions</div>
                        </div>

                        <div className="react-list-body">
                            {loading ? <div className="react-empty-state">Loading directory...</div> : null}
                            {!loading && entries.length === 0 ? <div className="react-empty-state">This directory is empty.</div> : null}
                            {!loading ? entries.map((entry) => {
                                const entryPath = normalizePath(`${currentPath === '/' ? '' : currentPath}/${entry.name || ''}`);
                                const isMenuOpen = menuPath === entryPath;
                                return (
                                    <div key={entryPath} className="react-list-row">
                                        <button
                                            type="button"
                                            className="react-file-cell"
                                            onClick={() => {
                                                setMenuPath('');
                                                if (entry.isDirectory) setCurrentPath(entryPath);
                                            }}
                                        >
                                            <i className={`bi ${entry.isDirectory ? 'bi-folder-fill' : 'bi-file-earmark-text'}`}></i>
                                            <div>
                                                <strong>{entry.name || 'Unnamed item'}</strong>
                                                <span>{entry.isDirectory ? 'Folder' : (entry.permissions || 'File')}</span>
                                            </div>
                                        </button>
                                        <div className="react-row-meta">{formatDate(entry.modified)}</div>
                                        <div className="react-row-meta">{entry.isDirectory ? 'Folder' : formatBytes(entry.size)}</div>
                                        <div className="react-row-actions">
                                            <button type="button" className="react-ui-button is-ghost is-small" onClick={() => setMenuPath(isMenuOpen ? '' : entryPath)}>
                                                <i className="bi bi-three-dots"></i>
                                            </button>
                                            {isMenuOpen ? (
                                                <div className="react-row-menu">
                                                    {entry.isDirectory ? (
                                                        <button type="button" className="react-row-menu-item" onClick={() => { setCurrentPath(entryPath); setMenuPath(''); }}>Open Folder</button>
                                                    ) : (
                                                        <>
                                                            <a className="react-row-menu-item" href={`${manager.editUrlBase}?path=${encodeURIComponent(entryPath)}`}>Edit</a>
                                                            <a className="react-row-menu-item" href={`${manager.previewUrlBase}?path=${encodeURIComponent(entryPath)}`}>Preview</a>
                                                            {permissions.canDownloadFiles ? (
                                                                <a className="react-row-menu-item" href={`${manager.downloadUrlBase}?path=${encodeURIComponent(entryPath)}`}>Download</a>
                                                            ) : null}
                                                        </>
                                                    )}
                                                    <a className="react-row-menu-item" href={`${manager.legacyUrl}?legacy=1&path=${encodeURIComponent(currentPath)}`}>Open Legacy Manager</a>
                                                </div>
                                            ) : null}
                                        </div>
                                    </div>
                                );
                            }) : null}
                        </div>
                    </section>
                </section>
            </main>
        </ReactAppShell>
    );
}

export default ServerFilesPage;

if (root) {
    root.render(<ServerFilesPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
