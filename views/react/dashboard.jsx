import React from 'react';
import { createRoot } from 'react-dom/client';
import { Link } from 'react-router-dom';
import { ReactRoutes } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ServerRow from './components/ServerRow.jsx';
import Spinner from './components/Spinner.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'dashboard';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function DashboardPage({ pageData = data }) {
    const [servers, setServers] = React.useState(Array.isArray(pageData.servers) ? pageData.servers : null);
    
    // Simulate loading for purely visual feedback if pageData loaded quickly
    React.useEffect(() => {
        if (!pageData.servers) {
            // Ideally fetch here, but pageData provides it
            setServers([]);
        } else {
            setServers(pageData.servers);
        }
    }, [pageData]);

    const isAdminDashboard = Boolean(pageData.isAdminDashboard);

    return (
        <ReactAppShell pageData={pageData} subtitle="React view beta">
            <PageContentBlock 
                title={isAdminDashboard ? "System Overview" : "Dashboard"} 
                description={isAdminDashboard ? "Viewing all active servers across the system." : "Individual overview of your servers and instances."}
            >
                {pageData.user?.isAdmin && (
                    <div className="flex justify-between items-center mb-6 bg-neutral-800/50 border border-neutral-700/50 p-4 rounded-xl">
                        <div className="flex items-center gap-3">
                            <div className={`w-3 h-3 rounded-full ${isAdminDashboard ? 'bg-primary-500 animate-pulse' : 'bg-neutral-600'}`}></div>
                            <span className="text-sm font-bold text-neutral-300 uppercase tracking-widest">
                                {isAdminDashboard ? 'Admin View: All Servers' : 'Private View: My Servers'}
                            </span>
                        </div>
                        <a 
                            href={isAdminDashboard ? '/' : '/?others=true'}
                            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all ${isAdminDashboard ? 'bg-primary-600 hover:bg-primary-500 text-white shadow-lg shadow-primary-900/20' : 'bg-neutral-700 hover:bg-neutral-600 text-neutral-300'}`}
                        >
                            <i className={`bi ${isAdminDashboard ? 'bi-shield-check' : 'bi-shield-lock'} me-2`}></i>
                            {isAdminDashboard ? 'Exit Admin Mode' : 'Enter Admin Mode'}
                        </a>
                    </div>
                )}
                
                {!servers ? (
                    <Spinner centered size="large" />
                ) : servers.length > 0 ? (
                    <div className="flex flex-col gap-2">
                        {servers.map((server) => (
                            <ServerRow
                                key={server.id || server.containerId}
                                server={server}
                                isAdminDashboard={isAdminDashboard}
                            />
                        ))}
                    </div>
                ) : (
                    <p className="text-center text-sm text-neutral-400 mt-10">
                        There are no servers associated with your account.
                    </p>
                )}
            </PageContentBlock>
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
