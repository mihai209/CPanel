import React from 'react';
import { createRoot } from 'react-dom/client';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const root = createRoot(document.getElementById('reactRoot'));

function MetricCard({ label, value, subtitle, icon }) {
    return (
        <div className="react-card">
            <div className="react-pill mb-2">
                <i className={`bi ${icon}`}></i>
                {label}
            </div>
            <div className="react-metric-value">{String(value)}</div>
            <div className="react-card-subtle mt-2">{subtitle}</div>
        </div>
    );
}

function statusClass(status) {
    return `react-status react-status-${String(status || 'unknown').toLowerCase()}`;
}

function ServerCard({ server, showOwner }) {
    return (
        <a className="react-server-card" href={`/server/${server.containerId}`}>
            <div>
                <div className="react-server-name">{server.name || 'Unnamed Server'}</div>
                <div className="react-server-meta">
                    {server.description || `CPU ${server.cpu}% · RAM ${server.memory} MB · Disk ${server.disk} MB`}
                </div>
                {Array.isArray(server.tags) && server.tags.length > 0 ? (
                    <div className="d-flex flex-wrap gap-2 mt-3">
                        {server.tags.slice(0, 4).map((tag) => (
                            <span key={tag} className="react-pill">{tag}</span>
                        ))}
                    </div>
                ) : null}
            </div>
            <div className="text-end">
                <div className={statusClass(server.status)}>
                    <span className="react-status-dot"></span>
                    <span>{String(server.status || 'unknown')}</span>
                </div>
                {showOwner && server.ownerUsername ? (
                    <div className="react-server-meta mt-2">Owner: @{server.ownerUsername}</div>
                ) : null}
            </div>
        </a>
    );
}

function FeedItem({ title, detail }) {
    return (
        <div className="react-feed-item">
            <strong>{title}</strong>
            {detail ? <div className="react-card-subtle">{detail}</div> : null}
        </div>
    );
}

function DashboardApp() {
    const servers = Array.isArray(data.servers) ? data.servers : [];
    const incidents = Array.isArray(data.openIncidents) ? data.openIncidents : [];
    const maintenance = Array.isArray(data.pendingMaintenance) ? data.pendingMaintenance : [];
    const security = Array.isArray(data.openSecurityAlerts) ? data.openSecurityAlerts : [];
    const serverCount = servers.length;
    const runningCount = servers.filter((server) => String(server.status || '').toLowerCase() === 'running').length;
    const installCount = servers.filter((server) => ['installing', 'reinstalling', 'starting'].includes(String(server.status || '').toLowerCase())).length;
    const feedEntries = [
        ...incidents.slice(0, 2).map((entry, index) => ({
            key: `incident-${index}`,
            title: entry && (entry.title || entry.name || `Incident ${index + 1}`),
            detail: entry && (entry.description || entry.status || '')
        })),
        ...maintenance.slice(0, 2).map((entry, index) => ({
            key: `maintenance-${index}`,
            title: entry && (entry.title || entry.name || `Maintenance ${index + 1}`),
            detail: entry && (entry.description || entry.status || '')
        })),
        ...security.slice(0, 2).map((entry, index) => ({
            key: `security-${index}`,
            title: entry && (entry.title || entry.name || `Security ${index + 1}`),
            detail: entry && (entry.description || entry.status || '')
        }))
    ];

    return (
        <div className="react-shell">
            <aside className="react-sidebar">
                <div className="react-brand">
                    <div className="react-brand-mark">
                        <i className="bi bi-grid-1x2-fill"></i>
                    </div>
                    <div>
                        <div className="react-brand-title">{(data.brandName || 'CPanel') + ' React'}</div>
                        <div className="react-brand-subtitle">Experimental renderer</div>
                    </div>
                </div>

                <div className="react-nav">
                    <a className="react-nav-link is-active" href="/dashboard">
                        <div className="react-nav-link-label">
                            <i className="bi bi-house-door"></i>
                            <div>
                                <div>Dashboard</div>
                                <small>React beta</small>
                            </div>
                        </div>
                        <i className="bi bi-arrow-up-right"></i>
                    </a>
                    <a className="react-nav-link" href="/experimental-features">
                        <div className="react-nav-link-label">
                            <i className="bi bi-beaker"></i>
                            <div>
                                <div>Experimental</div>
                                <small>Flags and betas</small>
                            </div>
                        </div>
                        <i className="bi bi-arrow-up-right"></i>
                    </a>
                    <a className="react-nav-link" href="/account">
                        <div className="react-nav-link-label">
                            <i className="bi bi-person"></i>
                            <div>
                                <div>Account</div>
                                <small>Session and profile</small>
                            </div>
                        </div>
                        <i className="bi bi-arrow-up-right"></i>
                    </a>
                    <a className="react-nav-link" href="/themes">
                        <div className="react-nav-link-label">
                            <i className="bi bi-palette2"></i>
                            <div>
                                <div>Themes</div>
                                <small>Legacy theme manager</small>
                            </div>
                        </div>
                        <i className="bi bi-arrow-up-right"></i>
                    </a>
                </div>

                <div className="react-sidebar-meta mt-4">
                    <div className="react-pill">{serverCount} servers tracked</div>
                    <div className="react-pill">{(data.dashboardFolders || []).length} folders</div>
                    <div className="react-pill">{(data.dashboardTags || []).length} tags</div>
                </div>
            </aside>

            <main className="react-main">
                <div className="react-topbar">
                    <div>
                        <h1>Dashboard</h1>
                        <p>React beta shell for migrated surfaces. Non-migrated pages continue using the legacy renderer.</p>
                    </div>
                    <div className="react-user-chip">
                        <i className="bi bi-person-circle"></i>
                        <span>{data.user && data.user.username ? `@${data.user.username}` : 'Unknown'}</span>
                    </div>
                </div>

                <div className="react-banner">
                    <div className="fw-semibold mb-1">React beta is enabled</div>
                    <div className="react-card-subtle">
                        This renderer uses a fixed dark palette and ignores custom themes. Use Experimental Features to switch back whenever you want the stable EJS layout.
                    </div>
                </div>

                <div className="react-grid metrics">
                    <MetricCard label="Servers" value={serverCount} subtitle={`${runningCount} running right now`} icon="bi-hdd-stack" />
                    <MetricCard label="Provisioning" value={installCount} subtitle="Install, reinstall, and startup transitions" icon="bi-arrow-repeat" />
                    <MetricCard label="Incidents" value={incidents.length} subtitle="Open incident records" icon="bi-exclamation-diamond" />
                    <MetricCard label="Maintenance" value={maintenance.length} subtitle="Planned maintenance windows" icon="bi-tools" />
                </div>

                <div className="react-grid content mt-4">
                    <section className="react-card">
                        <div className="d-flex justify-content-between align-items-start gap-3">
                            <div>
                                <h2>Server Fleet</h2>
                                <div className="react-card-subtle">
                                    Current server inventory with live status snapshots from the existing panel data.
                                </div>
                            </div>
                            <a href="/dashboard" className="react-pill text-decoration-none">
                                <i className="bi bi-layout-text-window-reverse"></i>
                                Legacy dashboard
                            </a>
                        </div>
                        <div className="react-server-list">
                            {servers.length > 0 ? (
                                servers.map((server) => (
                                    <ServerCard key={server.id || server.containerId} server={server} showOwner={Boolean(data.isAdminDashboard)} />
                                ))
                            ) : (
                                <FeedItem title="No servers found" detail="Create a server or switch back to the legacy renderer if you expected content here." />
                            )}
                        </div>
                    </section>

                    <aside className="d-grid gap-4">
                        <section className="react-card">
                            <h3>Operations Feed</h3>
                            <div className="react-card-subtle">Highest-priority incident, maintenance, and security signals.</div>
                            <div className="react-feed-list">
                                {feedEntries.length > 0 ? (
                                    feedEntries.map((entry) => (
                                        <FeedItem key={entry.key} title={entry.title} detail={entry.detail} />
                                    ))
                                ) : (
                                    <FeedItem title="No active feed items" detail="Nothing urgent is currently queued in the dashboard feed." />
                                )}
                            </div>
                        </section>

                        <section className="react-card">
                            <h3>Current Coverage</h3>
                            <div className="react-feed-list">
                                <FeedItem title="React pages installed" detail="Dashboard is rendered from views/react/dashboard.jsx in this build." />
                                <FeedItem title="Legacy fallback remains active" detail="Server pages and the rest of the panel stay on EJS until their React pages are added." />
                            </div>
                        </section>
                    </aside>
                </div>
            </main>
        </div>
    );
}

root.render(<DashboardApp />);
if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
    window.__CPANEL_REACT_BOOTED__();
}
