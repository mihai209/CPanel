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

function formatMetricValue(val) {
    return Number(val || 0).toLocaleString();
}

function Announcer({ settings = {} }) {
    const enabled = String(settings.extensionAnnouncerEnabled || 'false') === 'true';
    const message = String(settings.extensionAnnouncerMessage || '').trim();
    if (!enabled || !message) return null;

    const severity = String(settings.extensionAnnouncerSeverity || 'normal').toLowerCase();
    const configs = {
        normal:   { badge: 'NORMAL',   bg: 'bg-green-500/10', border: 'border-green-500/20', text: 'text-green-300' },
        warning:  { badge: 'WARNING',  bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', text: 'text-yellow-300' },
        critical: { badge: 'CRITICAL', bg: 'bg-red-500/10',    border: 'border-red-500/20',    text: 'text-red-300' }
    };
    const conf = configs[severity] || configs.normal;

    return (
        <div className={`mb-6 p-4 rounded-2xl border ${conf.bg} ${conf.border} shadow-lg shadow-black/20 group relative overflow-hidden`}>
            <div className="absolute -right-4 -top-4 opacity-5 group-hover:opacity-10 transition-opacity duration-700">
                <i className="bi bi-megaphone-fill text-8xl -rotate-12"></i>
            </div>
            <div className="flex items-center gap-3 mb-2">
                <span className={`text-[10px] font-black uppercase tracking-[0.2em] px-2.5 py-1 rounded-lg bg-neutral-900 shadow-inner ${conf.text}`}>
                    <i className="bi bi-megaphone me-1.5"></i>
                    Broadcast • {conf.badge}
                </span>
            </div>
            <p className="text-sm text-neutral-200 leading-relaxed font-medium">
                {message}
            </p>
        </div>
    );
}

function MetricCard({ label, value, icon, tone = 'neutral' }) {
    const colors = {
        success: 'text-green-400 group-hover:text-green-300',
        warning: 'text-yellow-400 group-hover:text-yellow-300',
        danger:  'text-red-400 group-hover:text-red-300',
        neutral: 'text-primary-400 group-hover:text-primary-300'
    };
    return (
        <div className="group relative">
            <div className="absolute -inset-0.5 bg-gradient-to-br from-neutral-800 to-neutral-800/20 rounded-2xl blur opacity-30 group-hover:opacity-60 transition duration-500"></div>
            <div className="relative bg-neutral-900/40 backdrop-blur-xl border border-neutral-800/50 p-5 rounded-2xl h-full transition-all duration-300 hover:border-neutral-700/50">
                <div className="flex justify-between items-start mb-3">
                    <span className="text-[10px] font-black text-neutral-500 uppercase tracking-widest">{label}</span>
                    <i className={`bi ${icon} text-lg opacity-40 group-hover:opacity-100 transition-opacity ${colors[tone]}`}></i>
                </div>
                <div className="text-2xl font-black text-white tracking-tight tabular-nums">
                    {value}
                </div>
            </div>
        </div>
    );
}

function VersionStatusBanner({ status }) {
    if (!status || !status.message) return null;

    const configs = {
        success: {
            icon: 'bi-check-circle-fill',
            bg: 'bg-green-500/10',
            border: 'border-green-500/20',
            text: 'text-green-400',
            accent: 'bg-green-500'
        },
        warning: {
            icon: 'bi-exclamation-triangle-fill',
            bg: 'bg-yellow-500/10',
            border: 'border-yellow-500/20',
            text: 'text-yellow-400',
            accent: 'bg-yellow-500'
        },
        error: {
            icon: 'bi-x-circle-fill',
            bg: 'bg-red-500/10',
            border: 'border-red-500/20',
            text: 'text-red-400',
            accent: 'bg-red-500'
        }
    };

    const conf = configs[status.type] || configs.success;

    return (
        <div className={`mb-8 p-5 rounded-[2rem] border backdrop-blur-md shadow-2xl transition-all duration-500 hover:shadow-primary-900/10 ${conf.bg} ${conf.border}`}>
            <div className="flex items-center gap-4">
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center shadow-lg ${conf.accent} text-white`}>
                    <i className={`bi ${conf.icon} text-lg`}></i>
                </div>
                <div className="flex-1">
                    <div className="flex items-center gap-2 mb-0.5">
                        <span className={`text-[10px] font-black uppercase tracking-[0.2em] ${conf.text}`}>System Update Status</span>
                        <span className="w-1 h-1 rounded-full bg-neutral-600"></span>
                        <span className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest">{status.currentVersion}</span>
                    </div>
                    <p className="text-sm text-neutral-200 font-medium leading-relaxed">
                        {status.message}
                    </p>
                </div>
                {status.type === 'warning' && (
                    <a 
                        href="/admin/system" 
                        className="px-6 py-2.5 bg-neutral-900/80 hover:bg-neutral-800 text-white rounded-xl text-[10px] font-black uppercase tracking-[0.2em] border border-neutral-700/50 transition-all active:scale-95 whitespace-nowrap"
                    >
                        View Updates
                    </a>
                )}
            </div>
        </div>
    );
}

function OpsFeedItem({ entry, tone = 'neutral', type = 'incident' }) {

    const severityColors = {
        critical: 'bg-red-500 text-white',
        warning:  'bg-yellow-500 text-neutral-900',
        normal:   'bg-green-600 text-white'
    };
    const toneColor = severityColors[String(entry.severity || '').toLowerCase()] || 'bg-neutral-600';
    
    return (
        <div className="p-4 bg-neutral-900/50 border border-neutral-800/80 rounded-xl hover:border-neutral-700 transition-colors">
            <div className="flex justify-between items-start gap-3 mb-2">
                <h4 className="text-sm font-bold text-neutral-100 leading-snug">{entry.title}</h4>
                <span className={`text-[9px] px-2 py-0.5 rounded-full font-black uppercase tracking-widest ${toneColor}`}>
                    {entry.severity || (type === 'maintenance' ? 'PLANNED' : 'INFO')}
                </span>
            </div>
            <div className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-2 opacity-70">
                {type === 'maintenance' 
                    ? `Window: ${new Date(entry.startsAtMs).toLocaleString()} -> ${new Date(entry.endsAtMs).toLocaleString()}`
                    : `Reported: ${new Date(entry.createdAtMs).toLocaleString()}`
                }
            </div>
            {entry.message && (
                <p className="text-xs text-neutral-300 leading-relaxed opacity-90 border-t border-neutral-800 pt-2 mt-2 italic">
                    {entry.message}
                </p>
            )}
        </div>
    );
}

export function DashboardPage({ pageData = data }) {
    const [servers, setServers] = React.useState(Array.isArray(pageData.servers) ? pageData.servers : null);
    const [searchQuery, setSearchQuery] = React.useState(() => {
        if (typeof window !== 'undefined') {
            return new URLSearchParams(window.location.search).get('search') || '';
        }
        return '';
    });
    const [selectedUser, setSelectedUser] = React.useState('');
    const [selectedFolder, setSelectedFolder] = React.useState('');
    const [selectedTag, setSelectedTag] = React.useState('');
    const [sortMode, setSortMode] = React.useState('latest'); // latest, alphabetical, custom
    const [layout, setLayout] = React.useState(() => {
        const raw = pageData.dashboardLayout || {};
        return {
            metrics: raw.metrics !== false,
            announcements: raw.announcements !== false,
            opsFeed: raw.opsFeed !== false,
            filters: raw.filters !== false,
            resourcePills: raw.resourcePills !== false
        };
    });
    const [showCustomize, setShowCustomize] = React.useState(false);

    React.useEffect(() => {
        const handleSearch = (e) => {
            setSearchQuery(e.detail || '');
        };
        window.addEventListener('dashboard-search', handleSearch);
        return () => window.removeEventListener('dashboard-search', handleSearch);
    }, []);
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
        let filtered = [...servers];
        
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

        if (selectedFolder) {
            filtered = filtered.filter(s => String(s.folder || '').trim() === selectedFolder);
        }

        if (selectedTag) {
            filtered = filtered.filter(s => Array.isArray(s.tags) && s.tags.includes(selectedTag));
        }

        // Sorting
        if (sortMode === 'alphabetical') {
            filtered.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
        } else if (sortMode === 'latest') {
            // Assume the default from server is latest, otherwise we'd need timestamps
            // If they aren't sorted by latest initially, we can't do much without more data
        }

        return filtered;
    }, [servers, searchQuery, selectedUser, selectedFolder, selectedTag, sortMode, isViewingAllServers]);

    return (
        <ReactAppShell pageData={pageData} subtitle="React view beta">
            <PageContentBlock 
                title={isViewingAllServers ? "System Overview" : "Dashboard"} 
                description={isViewingAllServers ? "Viewing all active servers across the system." : "Individual overview of your servers and instances."}
            >
                {layout.announcements && <Announcer settings={pageData.settings} />}
                
                {pageData.versionStatus && pageData.isAdminDashboard && (
                    <VersionStatusBanner status={pageData.versionStatus} />
                )}

                {layout.metrics && (
                    <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
                        <MetricCard label="Total Nodes" value={formatMetricValue(pageData.totalServers)} icon="bi-server" />
                        <MetricCard label="Operational" value={formatMetricValue(pageData.runningServers)} icon="bi-activity" tone="success" />
                        <MetricCard label="Awaiting" value={formatMetricValue(pageData.installingServers)} icon="bi-hourglass-split" tone="warning" />
                        <MetricCard label="Suspended" value={formatMetricValue(pageData.suspendedServers)} icon="bi-shield-exclamation" tone="danger" />
                        <MetricCard label="Wallet Buffer" value={`${formatMetricValue(pageData.user?.coins)} 🪙`} icon="bi-wallet2" />
                    </div>
                )}

                {layout.opsFeed && (
                    (Array.isArray(pageData.openIncidents) && pageData.openIncidents.length > 0) ||
                    (Array.isArray(pageData.pendingMaintenance) && pageData.pendingMaintenance.length > 0) ||
                    (Array.isArray(pageData.openSecurityAlerts) && pageData.openSecurityAlerts.length > 0)
                ) && (
                    <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 mb-10">
                        {Array.isArray(pageData.openIncidents) && pageData.openIncidents.length > 0 && (
                            <div className="flex flex-col gap-4">
                                <h3 className="text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] flex items-center gap-2">
                                    <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span> Open Incidents
                                </h3>
                                <div className="flex flex-col gap-3">
                                    {pageData.openIncidents.map(e => <OpsFeedItem key={e.id || e.title} entry={e} type="incident" />)}
                                </div>
                            </div>
                        )}
                        {Array.isArray(pageData.pendingMaintenance) && pageData.pendingMaintenance.length > 0 && (
                            <div className="flex flex-col gap-4">
                                <h3 className="text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] flex items-center gap-2">
                                    <span className="w-1.5 h-1.5 rounded-full bg-primary-500"></span> Maintenance
                                </h3>
                                <div className="flex flex-col gap-3">
                                    {pageData.pendingMaintenance.map(e => <OpsFeedItem key={e.id || e.title} entry={e} type="maintenance" />)}
                                </div>
                            </div>
                        )}
                        {Array.isArray(pageData.openSecurityAlerts) && pageData.openSecurityAlerts.length > 0 && (
                            <div className="flex flex-col gap-4">
                                <h3 className="text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] flex items-center gap-2">
                                    <span className="w-1.5 h-1.5 rounded-full bg-yellow-500"></span> Security Alerts
                                </h3>
                                <div className="flex flex-col gap-3">
                                    {pageData.openSecurityAlerts.map(e => <OpsFeedItem key={e.id || e.title} entry={e} type="security" />)}
                                </div>
                            </div>
                        )}
                    </div>
                )}

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
                            <div className="flex items-center gap-3">
                                <button 
                                    onClick={() => setShowCustomize(true)}
                                    className="p-4 rounded-xl bg-neutral-800 hover:bg-neutral-700 text-neutral-400 hover:text-white transition-all border border-neutral-700/50"
                                    title="Customize Layout"
                                >
                                    <i className="bi bi-layout-text-window-reverse text-lg"></i>
                                </button>
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
                    </div>
                )}

                {/* Filter & Action Controls */}
                <div className="mb-8 flex flex-col xl:flex-row justify-between items-start xl:items-center gap-6">
                    <div className="flex flex-wrap items-center gap-3 w-full xl:w-auto">
                        {String(pageData.settings?.featureUserCreateEnabled) === 'true' && (
                            <>
                                <a href="/user/create" className="px-6 py-3 bg-primary-600 hover:bg-primary-500 text-white rounded-xl text-[10px] font-black uppercase tracking-[0.2em] shadow-lg shadow-primary-900/20 transition-all active:scale-95 flex items-center gap-2">
                                    <i className="bi bi-plus-lg text-sm"></i> Create Server
                                </a>
                                <a href="/store" className="px-6 py-3 bg-neutral-800 hover:bg-neutral-700 text-neutral-200 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] border border-neutral-700 transition-all flex items-center gap-2">
                                    <i className="bi bi-shop"></i> Store
                                </a>
                                <div className="hidden xl:block w-px h-8 bg-neutral-800 mx-2"></div>
                            </>
                        )}
                        
                        {layout.filters && servers && servers.length > 0 && (
                            <div className="flex flex-wrap items-center gap-3 flex-1 xl:flex-none">
                                <div className="relative group">
                                    <i className="bi bi-sort-down absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500 text-xs pointer-events-none transition-colors group-focus-within:text-primary-400"></i>
                                    <select
                                        value={sortMode}
                                        onChange={(e) => setSortMode(e.target.value)}
                                        className="bg-neutral-900/50 border border-neutral-800 rounded-xl py-2.5 pl-10 pr-10 text-[10px] font-black uppercase tracking-widest text-neutral-400 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 transition-all appearance-none cursor-pointer"
                                    >
                                        <option value="latest">Latest First</option>
                                        <option value="alphabetical">Alphabetical</option>
                                        <option value="custom">Custom Order</option>
                                    </select>
                                    <i className="bi bi-chevron-down absolute right-4 top-1/2 -translate-y-1/2 text-neutral-600 text-[8px] pointer-events-none"></i>
                                </div>

                                {Array.isArray(pageData.dashboardFolders) && pageData.dashboardFolders.length > 0 && (
                                    <div className="relative group">
                                        <i className="bi bi-folder2 absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500 text-xs pointer-events-none transition-colors group-focus-within:text-primary-400"></i>
                                        <select
                                            value={selectedFolder}
                                            onChange={(e) => setSelectedFolder(e.target.value)}
                                            className="bg-neutral-900/50 border border-neutral-800 rounded-xl py-2.5 pl-10 pr-10 text-[10px] font-black uppercase tracking-widest text-neutral-400 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 transition-all appearance-none cursor-pointer"
                                        >
                                            <option value="">All Folders</option>
                                            {pageData.dashboardFolders.map(f => <option key={f} value={f}>{f}</option>)}
                                        </select>
                                        <i className="bi bi-chevron-down absolute right-4 top-1/2 -translate-y-1/2 text-neutral-600 text-[8px] pointer-events-none"></i>
                                    </div>
                                )}

                                {Array.isArray(pageData.dashboardTags) && pageData.dashboardTags.length > 0 && (
                                    <div className="relative group">
                                        <i className="bi bi-tag absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500 text-xs pointer-events-none transition-colors group-focus-within:text-primary-400"></i>
                                        <select
                                            value={selectedTag}
                                            onChange={(e) => setSelectedTag(e.target.value)}
                                            className="bg-neutral-900/50 border border-neutral-800 rounded-xl py-2.5 pl-10 pr-10 text-[10px] font-black uppercase tracking-widest text-neutral-400 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 transition-all appearance-none cursor-pointer"
                                        >
                                            <option value="">All Tags</option>
                                            {pageData.dashboardTags.map(t => <option key={t} value={t}>{t}</option>)}
                                        </select>
                                        <i className="bi bi-chevron-down absolute right-4 top-1/2 -translate-y-1/2 text-neutral-600 text-[8px] pointer-events-none"></i>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    <div className="flex items-center gap-4 w-full xl:w-auto">
                        {isViewingAllServers && uniqueUsers.length > 0 && (
                            <div className="relative group flex-1 xl:flex-none">
                                <i className="bi bi-person absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500 text-xs pointer-events-none transition-colors group-focus-within:text-primary-400"></i>
                                <select
                                    value={selectedUser}
                                    onChange={(e) => setSelectedUser(e.target.value)}
                                    className="w-full bg-neutral-900/50 border border-neutral-800 rounded-xl py-2.5 pl-10 pr-10 text-[10px] font-black uppercase tracking-widest text-neutral-400 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 transition-all appearance-none cursor-pointer"
                                >
                                    <option value="">All Users</option>
                                    {uniqueUsers.map(u => (
                                        <option key={u} value={u}>{u}</option>
                                    ))}
                                </select>
                                <i className="bi bi-chevron-down absolute right-4 top-1/2 -translate-y-1/2 text-neutral-600 text-[8px] pointer-events-none"></i>
                            </div>
                        )}
                    </div>
                </div>
                
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
                    <div className="flex flex-col items-center justify-center py-24 bg-neutral-900/30 border border-neutral-800/50 border-dashed rounded-[3rem]">
                        <i className="bi bi-search text-5xl text-neutral-800 mb-6"></i>
                        <p className="text-center text-sm font-black text-neutral-500 uppercase tracking-[0.2em]">
                            No results match your criteria.
                        </p>
                        {(searchQuery || selectedUser || selectedFolder || selectedTag) && (
                            <button 
                                onClick={() => { setSearchQuery(''); setSelectedUser(''); setSelectedFolder(''); setSelectedTag(''); }}
                                className="mt-8 px-8 py-3 bg-neutral-800 hover:bg-neutral-700 text-neutral-300 rounded-2xl text-[10px] font-black uppercase tracking-[0.2em] transition-all border border-neutral-700/50"
                            >
                                Reset All Filters
                            </button>
                        )}
                    </div>
                )}
            </PageContentBlock>

            {/* Layout Customization Modal */}
            {showCustomize && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 sm:p-0">
                    <div className="absolute inset-0 bg-black/60 backdrop-blur-md" onClick={() => setShowCustomize(false)}></div>
                    <div className="relative w-full max-w-xl bg-neutral-900 border border-neutral-800 rounded-[2.5rem] shadow-2xl overflow-hidden ring-1 ring-white/10">
                        <div className="p-8 border-b border-neutral-800 flex justify-between items-center">
                            <div>
                                <h2 className="text-xl font-bold text-white tracking-tight">Customize Dashboard</h2>
                                <p className="text-xs text-neutral-500 font-bold uppercase tracking-widest mt-1">Configure your personal view prefs</p>
                            </div>
                            <button onClick={() => setShowCustomize(false)} className="w-10 h-10 flex items-center justify-center rounded-xl bg-neutral-800 text-neutral-400 hover:text-white transition-colors">
                                <i className="bi bi-x-lg"></i>
                            </button>
                        </div>
                        <div className="p-8 space-y-6">
                            {[
                                { id: 'metrics', label: 'Summary Metrics Bar', desc: 'Display total count, running status, and wallet balance.' },
                                { id: 'announcements', label: 'Broadcast Announcements', desc: 'Show important messages from system administrators.' },
                                { id: 'opsFeed', label: 'Operations Feed', desc: 'Monitor active incidents and scheduled maintenance.' },
                                { id: 'filters', label: 'Advanced Filter Controls', desc: 'Enable folder, tag, and custom sorting dropdowns.' },
                                { id: 'resourcePills', label: 'Internal Resource Data', desc: 'Show CPU/RAM usage directly on the server cards.' }
                            ].map(item => (
                                <div key={item.id} className="flex items-center justify-between gap-6 group">
                                    <div className="flex-1">
                                        <label htmlFor={item.id} className="block text-sm font-bold text-neutral-200 group-hover:text-primary-400 transition-colors cursor-pointer">{item.label}</label>
                                        <p className="text-xs text-neutral-500 mt-1">{item.desc}</p>
                                    </div>
                                    <div className="relative inline-flex items-center cursor-pointer">
                                        <input 
                                            type="checkbox" 
                                            id={item.id}
                                            className="sr-only peer"
                                            checked={layout[item.id]}
                                            onChange={() => setLayout(prev => ({ ...prev, [item.id]: !prev[item.id] }))}
                                        />
                                        <div className="w-12 h-6 bg-neutral-800 rounded-full peer peer-checked:bg-primary-600 after:content-[''] after:absolute after:top-[4px] after:left-[4px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-6 border border-neutral-700 peer-checked:border-primary-500 transition-colors"></div>
                                    </div>
                                </div>
                            ))}
                        </div>
                        <div className="p-8 bg-neutral-800/50 flex justify-between items-center">
                            <button 
                                onClick={() => setLayout({ metrics: true, announcements: true, opsFeed: true, filters: true, resourcePills: true })}
                                className="text-[10px] font-black text-neutral-500 hover:text-white uppercase tracking-widest transition-colors"
                            >
                                Reset to Defaults
                            </button>
                            <button 
                                onClick={() => setShowCustomize(false)}
                                className="px-8 py-3 bg-primary-600 hover:bg-primary-500 text-white rounded-xl text-[10px] font-black uppercase tracking-[0.2em] shadow-lg shadow-primary-900/20 transition-all active:scale-95"
                            >
                                Save Changes
                            </button>
                        </div>
                    </div>
                </div>
            )}
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
