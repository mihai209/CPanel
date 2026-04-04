import React from 'react';
import { createRoot } from 'react-dom/client';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const root = createRoot(document.getElementById('reactRoot'));

const STATUS_ORDER = ['running', 'starting', 'installing', 'reinstalling', 'stopped', 'offline', 'error'];

function formatStatus(status) {
    return String(status || 'unknown').replace(/_/g, ' ');
}

function statusClass(status) {
    return `react-fleet-status react-fleet-status-${String(status || 'unknown').toLowerCase()}`;
}

function FleetMetric({ icon, label, value, subvalue, tone = '' }) {
    return (
        <div className={`react-inline-metric ${tone ? `is-${tone}` : ''}`}>
            <div className="react-inline-metric-icon">
                <i className={`bi ${icon}`}></i>
            </div>
            <div>
                <div className="react-inline-metric-value">{value}</div>
                <div className="react-inline-metric-label">
                    {label}
                    {subvalue ? <span>{subvalue}</span> : null}
                </div>
            </div>
        </div>
    );
}

function UsageBar({ label, value, total, tone = 'blue' }) {
    const used = Number(value || 0);
    const cap = Number(total || 0);
    const width = cap > 0 ? Math.max(0, Math.min(100, (used / cap) * 100)) : 0;

    return (
        <div className="react-usage-block">
            <div className="react-usage-head">
                <span>{label}</span>
                <span>{used}{cap > 0 ? ` / ${cap}` : ''}</span>
            </div>
            <div className="react-usage-track">
                <div className={`react-usage-fill is-${tone}`} style={{ width: `${width}%` }}></div>
            </div>
        </div>
    );
}

function FleetRow({ server, showOwner }) {
    const status = String(server.status || 'unknown').toLowerCase();
    const accent = status === 'running' ? 'success' : (['installing', 'reinstalling', 'starting'].includes(status) ? 'warning' : 'muted');
    const tags = Array.isArray(server.tags) ? server.tags.filter(Boolean) : [];

    return (
        <a className="react-fleet-row" href={`/server/${server.containerId}`}>
            <div className={`react-fleet-avatar is-${accent}`}>
                <i className="bi bi-hdd-stack"></i>
            </div>

            <div className="react-fleet-main">
                <div className="react-fleet-title-row">
                    <div>
                        <div className="react-fleet-title">{server.name || 'Unnamed Server'}</div>
                        <div className="react-fleet-subtitle">
                            {server.description || 'No description provided yet.'}
                        </div>
                    </div>
                    <div className={statusClass(status)}>
                        <span className="react-fleet-status-dot"></span>
                        <span>{formatStatus(status)}</span>
                    </div>
                </div>

                <div className="react-fleet-meta-row">
                    <FleetMetric icon="bi bi-cpu" label="CPU" value={`${server.cpu || 0}%`} />
                    <FleetMetric icon="bi bi-memory" label="RAM" value={`${server.memory || 0} MB`} />
                    <FleetMetric icon="bi bi-device-hdd" label="Disk" value={`${server.disk || 0} MB`} />
                    <FleetMetric icon="bi bi-database" label="DB Limit" value={String(server.databaseLimit || 0)} />
                    {showOwner && server.ownerUsername ? (
                        <FleetMetric icon="bi bi-person" label="Owner" value={`@${server.ownerUsername}`} />
                    ) : null}
                </div>

                <div className="react-fleet-bottom-row">
                    <div className="react-fleet-usage-grid">
                        <UsageBar label="CPU Profile" value={server.cpu || 0} total={100} tone="blue" />
                        <UsageBar label="Memory Slice" value={server.memory || 0} total={Math.max(server.memory || 0, 2048)} tone="green" />
                        <UsageBar label="Disk Slice" value={server.disk || 0} total={Math.max(server.disk || 0, 20480)} tone="amber" />
                    </div>
                    <div className="react-fleet-tags">
                        {tags.length > 0 ? tags.slice(0, 4).map((tag) => (
                            <span key={tag} className="react-fleet-tag">{tag}</span>
                        )) : <span className="react-fleet-tag is-muted">No tags</span>}
                    </div>
                </div>
            </div>
        </a>
    );
}

function SignalCard({ title, eyebrow, count, note, icon, tone = '' }) {
    return (
        <div className={`react-signal-card ${tone ? `is-${tone}` : ''}`}>
            <div className="react-signal-icon">
                <i className={`bi ${icon}`}></i>
            </div>
            <div>
                <div className="react-signal-eyebrow">{eyebrow}</div>
                <div className="react-signal-title">{title}</div>
                <div className="react-signal-note">{note}</div>
            </div>
            <div className="react-signal-count">{count}</div>
        </div>
    );
}

function FeedItem({ title, detail, tone = '' }) {
    return (
        <div className={`react-feed-item ${tone ? `is-${tone}` : ''}`}>
            <strong>{title}</strong>
            {detail ? <div className="react-card-subtle">{detail}</div> : null}
        </div>
    );
}

function DashboardApp() {
    const servers = Array.isArray(data.servers) ? [...data.servers] : [];
    const incidents = Array.isArray(data.openIncidents) ? data.openIncidents : [];
    const maintenance = Array.isArray(data.pendingMaintenance) ? data.pendingMaintenance : [];
    const security = Array.isArray(data.openSecurityAlerts) ? data.openSecurityAlerts : [];

    servers.sort((a, b) => {
        const left = STATUS_ORDER.indexOf(String(a.status || '').toLowerCase());
        const right = STATUS_ORDER.indexOf(String(b.status || '').toLowerCase());
        return (left === -1 ? 999 : left) - (right === -1 ? 999 : right);
    });

    const serverCount = servers.length;
    const runningCount = servers.filter((server) => String(server.status || '').toLowerCase() === 'running').length;
    const provisioningCount = servers.filter((server) => ['installing', 'reinstalling', 'starting'].includes(String(server.status || '').toLowerCase())).length;
    const idleCount = servers.filter((server) => ['stopped', 'offline'].includes(String(server.status || '').toLowerCase())).length;
    const feedEntries = [
        ...incidents.slice(0, 2).map((entry, index) => ({
            key: `incident-${index}`,
            title: entry && (entry.title || entry.name || `Incident ${index + 1}`),
            detail: entry && (entry.description || entry.status || ''),
            tone: 'danger'
        })),
        ...maintenance.slice(0, 2).map((entry, index) => ({
            key: `maintenance-${index}`,
            title: entry && (entry.title || entry.name || `Maintenance ${index + 1}`),
            detail: entry && (entry.description || entry.status || ''),
            tone: 'warning'
        })),
        ...security.slice(0, 2).map((entry, index) => ({
            key: `security-${index}`,
            title: entry && (entry.title || entry.name || `Security ${index + 1}`),
            detail: entry && (entry.description || entry.status || ''),
            tone: 'info'
        }))
    ];

    return (
        <div className="react-dashboard-page">
            <div className="react-dashboard-shell">
                <header className="react-dashboard-topbar">
                    <div className="react-dashboard-brand">
                        <div className="react-dashboard-brand-mark">
                            <i className="bi bi-grid-3x3-gap-fill"></i>
                        </div>
                        <div>
                            <div className="react-dashboard-brand-title">{data.brandName || 'CPanel'}</div>
                            <div className="react-dashboard-brand-subtitle">React fleet board</div>
                        </div>
                    </div>

                    <nav className="react-dashboard-actions">
                        <a className="react-top-action is-active" href="/dashboard" title="Dashboard">
                            <i className="bi bi-house-door"></i>
                        </a>
                        <a className="react-top-action" href="/experimental-features" title="Experimental Features">
                            <i className="bi bi-beaker"></i>
                        </a>
                        <a className="react-top-action" href="/account" title="Account">
                            <i className="bi bi-person"></i>
                        </a>
                        <a className="react-top-action" href="/themes" title="Themes">
                            <i className="bi bi-palette2"></i>
                        </a>
                        <div className="react-user-chip">
                            <i className="bi bi-person-circle"></i>
                            <span>{data.user && data.user.username ? `@${data.user.username}` : 'Unknown'}</span>
                        </div>
                    </nav>
                </header>

                <section className="react-hero-strip">
                    <div>
                        <div className="react-hero-label">Fleet summary</div>
                        <h1>Keep the whole panel in one glance.</h1>
                        <p>
                            Fast status scan for runtime state, inventory pressure, and the signals that actually need attention.
                        </p>
                    </div>
                    <div className="react-hero-badges">
                        <span className="react-hero-badge">React beta</span>
                        <span className="react-hero-badge is-soft">No custom themes</span>
                    </div>
                </section>

                <section className="react-scoreboard">
                    <SignalCard title="Servers in fleet" eyebrow="Inventory" count={serverCount} note={`${runningCount} active, ${idleCount} idle`} icon="bi-hdd-stack" />
                    <SignalCard title="Provisioning queue" eyebrow="Runtime" count={provisioningCount} note="Install, reinstall, and first-start operations" icon="bi-arrow-repeat" tone="warning" />
                    <SignalCard title="Operational signals" eyebrow="Ops" count={incidents.length + maintenance.length + security.length} note="Incidents, maintenance, and security alerts" icon="bi-broadcast-pin" tone="info" />
                </section>

                <div className="react-board-grid">
                    <section className="react-board-panel">
                        <div className="react-panel-head">
                            <div>
                                <div className="react-panel-eyebrow">Your servers</div>
                                <h2>Fleet Board</h2>
                            </div>
                            <div className="react-panel-head-right">
                                <span className="react-panel-toggle">
                                    <span className="react-toggle-dot"></span>
                                    Showing your servers
                                </span>
                                <a href="/experimental/change-view" className="react-link-chip">
                                    Switch view
                                </a>
                            </div>
                        </div>

                        <div className="react-fleet-list">
                            {servers.length > 0 ? (
                                servers.map((server) => (
                                    <FleetRow
                                        key={server.id || server.containerId}
                                        server={server}
                                        showOwner={Boolean(data.isAdminDashboard)}
                                    />
                                ))
                            ) : (
                                <FeedItem title="No servers found" detail="Create a server first or switch back to the legacy renderer if this looks wrong." />
                            )}
                        </div>
                    </section>

                    <aside className="react-board-rail">
                        <section className="react-board-panel is-compact">
                            <div className="react-panel-eyebrow">Now visible</div>
                            <h3>Board Notes</h3>
                            <div className="react-feed-list">
                                <FeedItem title="React renderer is live" detail="This dashboard runs from views/react/dashboard.jsx and is bundled separately." tone="info" />
                                <FeedItem title="Legacy pages still exist" detail="Non-migrated routes continue to render through EJS until each page is ported." />
                            </div>
                        </section>

                        <section className="react-board-panel is-compact">
                            <div className="react-panel-eyebrow">Operational feed</div>
                            <h3>Priority Signals</h3>
                            <div className="react-feed-list">
                                {feedEntries.length > 0 ? (
                                    feedEntries.map((entry) => (
                                        <FeedItem key={entry.key} title={entry.title} detail={entry.detail} tone={entry.tone} />
                                    ))
                                ) : (
                                    <FeedItem title="No active feed items" detail="Nothing urgent is currently queued in the dashboard feed." />
                                )}
                            </div>
                        </section>

                        <section className="react-board-panel is-compact">
                            <div className="react-panel-eyebrow">Coverage</div>
                            <h3>Renderer Limits</h3>
                            <div className="react-mini-stats">
                                <div className="react-mini-stat">
                                    <span>Current React page</span>
                                    <strong>Dashboard</strong>
                                </div>
                                <div className="react-mini-stat">
                                    <span>Theme mode</span>
                                    <strong>Dark only</strong>
                                </div>
                                <div className="react-mini-stat">
                                    <span>Folder groups</span>
                                    <strong>{(data.dashboardFolders || []).length}</strong>
                                </div>
                                <div className="react-mini-stat">
                                    <span>Tag groups</span>
                                    <strong>{(data.dashboardTags || []).length}</strong>
                                </div>
                            </div>
                        </section>
                    </aside>
                </div>
            </div>
        </div>
    );
}

root.render(<DashboardApp />);
if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
    window.__CPANEL_REACT_BOOTED__();
}
