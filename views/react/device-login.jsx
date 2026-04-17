import React from 'react';
import { createRoot } from 'react-dom/client';
import { Link } from 'react-router-dom';
import { ReactRoutes } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

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
        <ReactAppShell pageData={pageData} subtitle="Device login history">
            <PageContentBlock title="Activity History">
                <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6 mb-6">
                    <div className="flex justify-between items-center">
                        <div>
                            <h2 className="text-lg font-bold text-neutral-100">Recent login activity</h2>
                            <p className="text-sm text-neutral-400 mt-1">Latest account access records across device and login flow.</p>
                        </div>
                        <Link to={ReactRoutes.account} className="bg-neutral-700 hover:bg-neutral-600 text-neutral-200 text-sm font-semibold py-2 px-4 rounded transition-colors hidden sm:block">
                            Back to Account
                        </Link>
                    </div>
                </div>

                <div className="flex flex-col gap-2">
                    {events.length > 0 ? (
                        events.map((entry) => (
                            <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between" key={entry.id || `${entry.ipAddress}-${entry.createdAt}`}>
                                <div className="flex items-center gap-4">
                                    <div className="bg-neutral-700 text-neutral-300 p-3 rounded-full flex items-center justify-center">
                                        <i className="bi bi-phone text-xl leading-none"></i>
                                    </div>
                                    <div>
                                        <div className="font-bold text-neutral-100">{entry.username || user.username || 'Unknown'}</div>
                                        <div className="text-sm text-neutral-400 mt-0.5">
                                            {`${entry.operatingSystem || 'Unknown OS'} • ${entry.loginType || 'Standard'} • ${entry.ipAddress || 'unknown'}`}
                                        </div>
                                    </div>
                                </div>
                                <div className="mt-4 md:mt-0 flex flex-col md:items-end">
                                    <div className="font-semibold text-neutral-200">{entry.location || 'Unknown'}</div>
                                    <div className="text-sm text-neutral-500 font-mono mt-0.5">{formatDate(entry.createdAt)}</div>
                                </div>
                            </div>
                        ))
                    ) : (
                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-8 text-center">
                            <p className="text-neutral-400">No login history yet.</p>
                        </div>
                    )}
                </div>
            </PageContentBlock>
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
