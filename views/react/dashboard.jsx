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
            <PageContentBlock title="Dashboard">
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
