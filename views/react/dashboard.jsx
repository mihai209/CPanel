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

    const isViewingAllServers = Boolean(pageData.showOthersServers);
    const userIsAdmin = Boolean(pageData.isAdminDashboard);

    return (
        <ReactAppShell pageData={pageData} subtitle="React view beta">
            <PageContentBlock 
                title={isViewingAllServers ? "System Overview" : "Dashboard"} 
                description={isViewingAllServers ? "Viewing all active servers across the system." : "Individual overview of your servers and instances."}
            >
                {userIsAdmin && (
                    <div className="mb-10 group relative">
                        <div className="absolute -inset-1 bg-gradient-to-r from-primary-600/20 to-purple-600/20 rounded-[2.5rem] blur-xl opacity-50 group-hover:opacity-100 transition duration-1000 group-hover:duration-200"></div>
                        <div className="relative flex flex-col sm:flex-row justify-between items-center bg-neutral-900/80 backdrop-blur-xl border border-neutral-800/50 p-6 sm:p-8 rounded-[2rem] shadow-2xl overflow-hidden ring-1 ring-white/5">
                            <div className="flex items-center gap-6 mb-6 sm:mb-0">
                                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center transition-all duration-500 shadow-inner ${isViewingAllServers ? 'bg-primary-500/10 text-primary-400 ring-2 ring-primary-500/20' : 'bg-neutral-800 text-neutral-500'}`}>
                                    <i className={`bi ${isViewingAllServers ? 'bi-shield-check' : 'bi-shield-lock'} text-2xl`}></i>
                                </div>
                                <div>
                                    <h4 className="text-sm font-black text-white uppercase tracking-[0.2em] leading-none mb-2">
                                        {isViewingAllServers ? 'System-Wide Administration' : 'Personal Instance Dashboard'}
                                    </h4>
                                    <p className="text-xs text-neutral-500 font-bold uppercase tracking-widest opacity-80">
                                        {isViewingAllServers ? 'Global visibility enabled: Viewing all network servers' : 'Filtered view: Only showing your private instances'}
                                    </p>
                                </div>
                            </div>
                            <a 
                                href={isViewingAllServers ? '/' : '/?others=true'}
                                className={`group relative px-8 py-4 rounded-xl text-xs font-black uppercase tracking-[0.25em] transition-all duration-300 flex items-center gap-3 overflow-hidden ${isViewingAllServers ? 'bg-neutral-800 hover:bg-neutral-700 text-primary-400 border border-neutral-700' : 'bg-primary-600 hover:bg-primary-500 text-white shadow-2xl shadow-primary-900/40'}`}
                            >
                                <span className="relative z-10 flex items-center gap-3">
                                    <i className={`bi ${isViewingAllServers ? 'bi-toggle-on text-lg' : 'bi-toggle-off text-lg opacity-50'}`}></i>
                                    {isViewingAllServers ? 'Leave Admin View' : 'Enter Admin View'}
                                </span>
                            </a>
                        </div>
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
                                isAdminDashboard={isViewingAllServers}
                            />
                        ))}
                    </div>
                ) : (
                    <div className="flex flex-col items-center justify-center py-24 bg-neutral-900/30 border border-neutral-800/50 border-dashed rounded-3xl">
                        <i className="bi bi-stack text-4xl text-neutral-800 mb-4"></i>
                        <p className="text-center text-sm font-bold text-neutral-500 uppercase tracking-widest">
                            {isViewingAllServers ? 'No servers found in the system.' : 'You do not have any active servers.'}
                        </p>
                    </div>
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
