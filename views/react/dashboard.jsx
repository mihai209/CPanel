import React from 'react';
import { createRoot } from 'react-dom/client';
import { Link } from 'react-router-dom';
import { ReactRoutes, buildServerConsoleRoute } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'dashboard';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function formatStatus(status) {
    const value = String(status || 'unknown').toLowerCase();
    return value.charAt(0).toUpperCase() + value.slice(1).replace(/_/g, ' ');
}

function metricTone(status) {
    const value = String(status || 'unknown').toLowerCase();
    if (value === 'running') return 'success';
    if (['installing', 'reinstalling', 'starting'].includes(value)) return 'warning';
    if (['stopped', 'offline', 'error'].includes(value)) return 'danger';
    return 'muted';
}

function ResourcePill({ icon, value, label, tone = '' }) {
    return (
        <div className={`react-resource-pill${tone ? ` is-${tone}` : ''}`}>
            <i className={`bi ${icon}`}></i>
            <div>
                <strong>{value}</strong>
                <span>{label}</span>
            </div>
        </div>
    );
}

function ServerRow({ server, isAdminDashboard }) {
    const status = String(server.status || 'unknown').toLowerCase();
    const description = server.description || 'No description provided yet.';

    return (
        <Link className="react-server-row" to={buildServerConsoleRoute(server.containerId)}>
            <div className={`react-server-icon is-${metricTone(status)}`}>
                <i className="bi bi-hdd-stack"></i>
            </div>

            <div className="react-server-main">
                <div className="react-server-head">
                    <div>
                        <div className="react-server-name">{server.name || 'Unnamed Server'}</div>
                        <div className="react-server-description">{description}</div>
                    </div>
                    <div className={`react-status-badge is-${metricTone(status)}`}>
                        <span className="react-status-dot"></span>
                        <span>{formatStatus(status)}</span>
                    </div>
                </div>

                <div className="react-server-resources">
                    <ResourcePill icon="bi-cpu" value={`${server.cpu || 0}%`} label="CPU" />
                    <ResourcePill icon="bi-memory" value={`${server.memory || 0} MB`} label="Memory" />
                    <ResourcePill icon="bi-device-hdd" value={`${server.disk || 0} MB`} label="Disk" />
                    <ResourcePill icon="bi-database" value={String(server.databaseLimit || 0)} label="Databases" />
                    {isAdminDashboard && server.ownerUsername ? (
                        <ResourcePill icon="bi-person" value={`@${server.ownerUsername}`} label="Owner" tone="info" />
                    ) : null}
                </div>
            </div>
        </Link>
    );
}

function SideItem({ title, value, note, tone = '' }) {
    return (
        <div className={`react-side-item${tone ? ` is-${tone}` : ''}`}>
            <div className="react-side-item-head">
                <strong>{title}</strong>
                <span>{value}</span>
            </div>
            <div className="react-side-item-note">{note}</div>
        </div>
    );
}

export function DashboardPage({ pageData = data }) {
    const servers = Array.isArray(pageData.servers) ? pageData.servers : [];
    const incidents = Array.isArray(pageData.openIncidents) ? pageData.openIncidents : [];
    const maintenance = Array.isArray(pageData.pendingMaintenance) ? pageData.pendingMaintenance : [];
    const security = Array.isArray(pageData.openSecurityAlerts) ? pageData.openSecurityAlerts : [];

    const runningCount = servers.filter((server) => String(server.status || '').toLowerCase() === 'running').length;
    const provisioningCount = servers.filter((server) => ['installing', 'reinstalling', 'starting'].includes(String(server.status || '').toLowerCase())).length;
    const offlineCount = servers.filter((server) => ['stopped', 'offline', 'error'].includes(String(server.status || '').toLowerCase())).length;
    const signalCount = incidents.length + maintenance.length + security.length;

    return (
        <ReactAppShell pageData={pageData} subtitle="React view beta">
            <main className="react-basic-grid">
                    <section className="react-basic-main">
                        <div className="react-basic-heading">
                            <div>
                                <h1>Servers</h1>
                                <p>Simple fleet view for the React renderer. Clean, fast, and focused on runtime state.</p>
                            </div>
                        <Link to={ReactRoutes.changeView} className="react-basic-link">
                            Change View
                        </Link>
                        </div>

                        <div className="react-server-list-scroll">
                            <div className="react-server-list">
                                {servers.length > 0 ? (
                                    servers.map((server) => (
                                        <ServerRow
                                            key={server.id || server.containerId}
                                            server={server}
                                            isAdminDashboard={Boolean(pageData.isAdminDashboard)}
                                        />
                                    ))
                                ) : (
                                    <div className="react-empty-state">
                                        <strong>No servers found</strong>
                                        <span>Create a server or switch back to the legacy view if this looks wrong.</span>
                                    </div>
                                )}
                            </div>
                        </div>
                    </section>

                    <aside className="react-basic-side">
                        <div className="react-side-card">
                            <div className="react-side-title">Overview</div>
                            <div className="react-side-list">
                                <SideItem title="Servers" value={String(servers.length)} note={`${runningCount} running now`} />
                                <SideItem title="Provisioning" value={String(provisioningCount)} note="Installing, reinstalling, or starting" tone="warning" />
                                <SideItem title="Offline" value={String(offlineCount)} note="Stopped, offline, or error state" tone="danger" />
                            </div>
                        </div>

                        <div className="react-side-card">
                            <div className="react-side-title">Signals</div>
                            <div className="react-side-list">
                                <SideItem title="Incidents" value={String(incidents.length)} note="Open incident records" tone="danger" />
                                <SideItem title="Maintenance" value={String(maintenance.length)} note="Planned maintenance windows" tone="warning" />
                                <SideItem title="Security" value={String(security.length)} note="Open security alerts" tone="info" />
                                <SideItem title="Total" value={String(signalCount)} note="Combined platform signals" />
                            </div>
                        </div>

                        <div className="react-side-card">
                            <div className="react-side-title">Renderer</div>
                            <div className="react-renderer-note">
                                React uses a fixed dark theme here. Non-migrated pages still fall back to EJS.
                            </div>
                        </div>
                    </aside>
            </main>
        </ReactAppShell>
    );
}

export default DashboardPage;

if (root) {
    root.render(<DashboardPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
