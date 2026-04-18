import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Link } from 'react-router-dom';
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
    const [searchQuery, setSearchQuery] = React.useState('');
    const [selectedUser, setSelectedUser] = React.useState('');
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

    const uniqueUsers = React.useMemo(() => {
        if (!servers || !isViewingAllServers) return [];
        const users = new Set();
        servers.forEach(s => {
            if (s.owner && s.owner.username) {
                users.add(s.owner.username);
            }
        });
        return Array.from(users).sort();
    }, [servers, isViewingAllServers]);

    const filteredServers = React.useMemo(() => {
        if (!servers) return null;
        let filtered = servers;
        
        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            filtered = filtered.filter(s => 
                (s.name && s.name.toLowerCase().includes(query)) ||
                (s.containerId && s.containerId.toLowerCase().includes(query)) ||
                (s.owner && s.owner.username && s.owner.username.toLowerCase().includes(query))
            );
        }

        if (isViewingAllServers && selectedUser) {
            filtered = filtered.filter(s => s.owner && s.owner.username === selectedUser);
        }

        return filtered;
    }, [servers, searchQuery, selectedUser, isViewingAllServers]);

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
                                    <h4 className="text-[11px] font-black text-white uppercase tracking-[0.2em] leading-none mb-2 opacity-90">
                                        {isViewingAllServers ? 'System-Wide Administration' : 'Personal Instance Dashboard'}
                                    </h4>
                                    <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest opacity-70">
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

                {/* Filter Controls */}
                {servers && servers.length > 0 && (
                    <div className="mb-6 flex flex-col sm:flex-row justify-end items-end sm:items-center gap-4">
                        {isViewingAllServers && uniqueUsers.length > 0 && (
                            <div className="sm:w-64 shrink-0 relative flex items-center w-full sm:w-auto">
                                <i className="bi bi-funnel absolute left-4 text-neutral-500 pointer-events-none"></i>
                                <select
                                    value={selectedUser}
                                    onChange={(e) => setSelectedUser(e.target.value)}
                                    className="w-full bg-neutral-900/50 backdrop-blur-md border border-neutral-800/80 rounded-2xl py-3 pl-10 pr-10 text-sm text-neutral-200 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 transition-all appearance-none cursor-pointer hidden sm:block"
                                >
                                    <option value="">All Users</option>
                                    {uniqueUsers.map(u => (
                                        <option key={u} value={u}>{u}</option>
                                    ))}
                                </select>
                                <select
                                    value={selectedUser}
                                    onChange={(e) => setSelectedUser(e.target.value)}
                                    className="w-full bg-neutral-900/50 backdrop-blur-md border border-neutral-800/80 rounded-full py-3 pl-10 pr-10 text-sm text-neutral-200 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 transition-all appearance-none cursor-pointer sm:hidden"
                                >
                                    <option value="">All Users</option>
                                    {uniqueUsers.map(u => (
                                        <option key={u} value={u}>{u}</option>
                                    ))}
                                </select>
                                <i className="bi bi-chevron-down absolute right-4 text-neutral-600 pointer-events-none text-xs"></i>
                            </div>
                        )}
                        <div className={`relative transition-all duration-300 ease-in-out shrink-0 group right-0 overflow-hidden ${searchQuery ? 'w-full sm:w-80' : 'w-12 hover:w-full sm:hover:w-64 focus-within:w-full sm:focus-within:w-80'}`}>
                            <i className={`bi bi-search absolute left-0 w-12 h-12 flex items-center justify-center top-0 transition-colors pointer-events-none z-10 ${searchQuery ? 'text-primary-500' : 'text-neutral-500 group-hover:text-primary-400'}`}></i>
                            <input 
                                type="text"
                                placeholder="Search servers..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className={`w-full bg-neutral-900/50 backdrop-blur-md border border-neutral-800/80 h-12 pl-12 pr-10 text-sm text-neutral-200 placeholder-neutral-600 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 transition-all shadow-inner cursor-pointer focus:cursor-text group-hover:cursor-text ${searchQuery ? 'rounded-2xl' : 'rounded-full'}`}
                            />
                            {searchQuery && (
                                <button 
                                    onClick={() => setSearchQuery('')}
                                    className="absolute right-4 top-1/2 -translate-y-1/2 text-neutral-500 hover:text-neutral-300 transition-colors z-10"
                                >
                                    <i className="bi bi-x-circle-fill"></i>
                                </button>
                            )}
                        </div>
                    </div>
                )}
                
                {!servers ? (
                    <Spinner centered size="large" />
                ) : filteredServers.length > 0 ? (
                    <div className="flex flex-col gap-2">
                        {filteredServers.map((server) => (
                            <ServerRow
                                key={server.id || server.containerId}
                                server={server}
                                isAdminDashboard={isViewingAllServers}
                            />
                        ))}
                    </div>
                ) : (
                    <div className="flex flex-col items-center justify-center py-24 bg-neutral-900/30 border border-neutral-800/50 border-dashed rounded-3xl">
                        <i className="bi bi-search text-4xl text-neutral-800 mb-4"></i>
                        <p className="text-center text-sm font-bold text-neutral-500 uppercase tracking-widest">
                            No servers match your filters.
                        </p>
                        {(searchQuery || selectedUser) && (
                            <button 
                                onClick={() => { setSearchQuery(''); setSelectedUser(''); }}
                                className="mt-6 px-6 py-2.5 bg-neutral-800 hover:bg-neutral-700 text-neutral-300 rounded-xl text-xs font-black uppercase tracking-widest transition-colors"
                            >
                                Clear Filters
                            </button>
                        )}
                    </div>
                )}
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default DashboardPage;

if (root) {
    root.render(
        <BrowserRouter>
            <DashboardPage pageData={data} />
        </BrowserRouter>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
