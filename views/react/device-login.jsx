import React from 'react';
import { createRoot } from 'react-dom/client';
import { Link } from 'react-router-dom';
import { ReactRoutes } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'device-login';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function formatDate(value) {
    try {
        return new Date(value).toLocaleString();
    } catch {
        return String(value || '');
    }
}

export function DeviceLoginPage({ pageData = data }) {
    const user = pageData.user || {};
    const events = Array.isArray(pageData.events) ? pageData.events : [];

    return (
        <ReactAppShell pageData={pageData} subtitle="Device login history" pageClassName="react-experimental-page" shellClassName="react-experimental-shell">
            <main className="react-experimental-layout">
                    <div className="react-experimental-scroll">
                        <div className="react-account-card">
                            <div className="react-account-section-title">Recent login activity</div>
                            <div className="react-account-muted">Latest account access records across device and login flow.</div>
                            <div className="react-account-inline-actions">
                                <Link to={ReactRoutes.account} className="react-account-button is-ghost">Back to Account</Link>
                            </div>
                        </div>

                        <div className="react-account-provider-list" style={{ marginTop: '18px' }}>
                            {events.length > 0 ? (
                                events.map((entry) => (
                                    <div className="react-account-provider react-device-event" key={entry.id || `${entry.ipAddress}-${entry.createdAt}`}>
                                        <div className="react-account-provider-main">
                                            <i className="bi bi-phone"></i>
                                            <div>
                                                <strong>{entry.username || user.username || 'Unknown'}</strong>
                                                <span>{`${entry.operatingSystem || 'Unknown OS'} • ${entry.loginType || 'Standard'} • ${entry.ipAddress || 'unknown'}`}</span>
                                            </div>
                                        </div>
                                        <div className="react-device-event-meta">
                                            <strong>{entry.location || 'Unknown'}</strong>
                                            <span>{formatDate(entry.createdAt)}</span>
                                        </div>
                                    </div>
                                ))
                            ) : (
                                <div className="react-account-card">
                                    <div className="react-account-muted">No login history yet.</div>
                                </div>
                            )}
                        </div>
                    </div>
            </main>
        </ReactAppShell>
    );
}

export default DeviceLoginPage;

if (root) {
    root.render(<DeviceLoginPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
