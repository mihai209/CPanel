import React from 'react';
import { NavLink } from 'react-router-dom';
import { ReactRoutes, resolveBrandImage, resolveUserAvatar } from '../ReactRoutes.js';
import ProvisioningBarrier from './ProvisioningBarrier.jsx';
import GlobalStatusModal from './GlobalStatusModal.jsx';
import NotificationBell from './NotificationBell.jsx';
import GlobalSearch from './GlobalSearch.jsx';
import ServerNavbar from './ServerNavbar.jsx';

function InternalTopAction({ to, icon, title }) {
    return (
        <NavLink
            to={to}
            title={title}
            className={({ isActive }) => `text-neutral-400 hover:text-neutral-100 transition-colors p-2 rounded-full hover:bg-neutral-700 ${isActive ? 'text-neutral-100 bg-neutral-700' : ''}`}
        >
            <i className={`bi ${icon}`}></i>
        </NavLink>
    );
}

function PrimaryNavLink({ to, label }) {
    const currentPath = window.location.pathname;
    const isActive = currentPath === to || (to !== '/' && currentPath.startsWith(to));
    
    return (
        <a 
            href={to} 
            className={`px-4 py-3 text-sm font-semibold transition-colors ${isActive ? 'text-white border-b-2 border-primary-500' : 'text-neutral-400 hover:text-white'}`}
        >
            {label}
        </a>
    );
}

export default function ReactAppShell({
    pageData = {},
    subtitle = 'React view beta',
    pageClassName = '',
    shellClassName = '',
    children
}) {
    const brandImage = resolveBrandImage(pageData);
    const userAvatar = resolveUserAvatar(pageData.user || {}, brandImage);
    const [mobileNavOpen, setMobileNavOpen] = React.useState(false);
    const serverNavItems = Array.isArray(pageData.serverNavItems) ? pageData.serverNavItems : [];
    
    // Mimic the tabs used by pterodactyl
    const shellNavItems = [
        { to: ReactRoutes.dashboard, label: 'Dashboard' },
        { to: ReactRoutes.account, label: 'Account' }
    ];

    const isProvisioning = ['installing', 'reinstalling'].includes(pageData.server?.status);
    const blockedPageKeys = ['files', 'backups', 'dbs', 'network', 'users', 'api', 'schedules', 'startup', 'timeline'];
    const activeNavItem = serverNavItems.find(item => item.active);
    const shouldBlock = isProvisioning && activeNavItem && blockedPageKeys.includes(activeNavItem.key);

    return (
        <div className={`min-h-screen bg-neutral-900 text-neutral-200 flex flex-col ${pageClassName || ''}`}>
            
            {/* Top Navigation Bar */}
            <div className="bg-neutral-800 border-b border-neutral-700 w-full flex items-center justify-between px-4 lg:px-8 h-16 shrink-0">
                <div className="flex items-center gap-4">
                    <img src={brandImage} alt={pageData.brandName || 'CPanel'} className="w-8 h-8 rounded shrink-0" />
                    <div>
                        <div className="text-lg font-bold text-neutral-100 leading-tight">
                            {pageData.brandName || 'CPanel'}
                        </div>
                        <div className="text-xs text-neutral-400 font-semibold">{subtitle}</div>
                    </div>
                </div>

                {/* Desktop Tabs */}
                <nav className="hidden md:flex items-center h-full ml-10 flex-1">
                    {shellNavItems.map((item) => (
                        <PrimaryNavLink key={item.to} to={item.to} label={item.label} />
                    ))}
                    <div className="flex-1"></div>
                </nav>

                {/* Right Actions */}
                <div className="flex items-center gap-3 md:gap-4 shrink-0">
                    <button
                        type="button"
                        className="md:hidden text-neutral-400 hover:text-neutral-100 p-2"
                        title="Toggle navigation"
                        onClick={() => setMobileNavOpen(!mobileNavOpen)}
                    >
                        <i className="bi bi-list text-2xl"></i>
                    </button>
                    
                    <div className="hidden md:flex items-center gap-2">
                        {pageData.user?.isAdmin && (
                            <>
                                <a className="text-neutral-400 hover:text-neutral-100 transition-colors p-2 rounded-full hover:bg-neutral-700" href={ReactRoutes.admin} title="Admin Area">
                                    <i className="bi bi-gear-fill"></i>
                                </a>
                                <InternalTopAction to={ReactRoutes.connectorsCheck} icon="bi-cpu" title="Connectors Check" />
                            </>
                        )}
                        <div className="h-6 w-px bg-neutral-700 mx-1"></div>
                        <GlobalSearch />
                        <NotificationBell />
                        <div className="h-6 w-px bg-neutral-700 mx-2"></div>
                        <InternalTopAction to={ReactRoutes.experimentalFeatures} icon="bi-sliders" title="Experimental Features" />
                        <a className="text-neutral-400 hover:text-neutral-100 transition-colors p-2 rounded-full hover:bg-neutral-700" href={ReactRoutes.changeView} title="Exit Beta">
                            <i className="bi bi-door-open"></i>
                        </a>
                    </div>

                    <div className="flex items-center gap-3 pl-4 border-l border-neutral-700">
                        <span className="text-sm font-semibold hidden md:block">
                            {pageData.user?.username || 'Guest'}
                        </span>
                        <img
                            src={userAvatar}
                            alt="User Avatar"
                            className="w-8 h-8 rounded-full border border-neutral-600"
                        />
                    </div>
                </div>
            </div>

            {/* Mobile Nav Drawer */}
            {mobileNavOpen && (
                <div className="md:hidden bg-neutral-800 border-b border-neutral-700 flex flex-col">
                    {shellNavItems.map((item) => (
                        <NavLink 
                            key={item.to} 
                            to={item.to} 
                            className={({ isActive }) => `px-4 py-3 text-sm font-semibold border-l-4 ${isActive ? 'text-white border-primary-500 bg-neutral-700/50' : 'text-neutral-400 font-medium border-transparent hover:text-white'}`}
                        >
                            {item.label}
                        </NavLink>
                    ))}
                    <NavLink to={ReactRoutes.changeView} className="px-4 py-3 text-sm font-semibold border-l-4 border-transparent text-neutral-400 hover:text-white">
                        Exit Beta Mode
                    </NavLink>
                </div>
            )}

            {/* Server Deep Navigation — delegated to ServerNavbar */}
            {serverNavItems.length > 0 && <ServerNavbar pageData={pageData} />}

            {/* Main Content Area */}
            <main className="flex-1 w-full bg-neutral-900">
                {shouldBlock ? (
                    <ProvisioningBarrier status={pageData.server.status} containerId={pageData.server.containerId} />
                ) : (
                    children
                )}
            </main>

            {/* Global Modals & Toasts */}
            <GlobalStatusModal />

            {/* Global Footer */}
            <footer className="w-full py-8 border-t border-neutral-800 bg-neutral-900 mt-auto">
                <div className="px-4 lg:px-8 flex flex-col md:flex-row justify-between items-center gap-4">
                    <div className="flex items-center gap-3">
                        <span className="text-xs font-black text-neutral-100 uppercase tracking-[0.2em] opacity-80">
                            CPanel Rocky &copy; 2026
                        </span>
                    </div>
                    <div>
                        <a 
                            href="https://github.com/mihai209" 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-[10px] font-bold text-neutral-500 hover:text-primary-400 transition-colors uppercase tracking-[0.1em] flex items-center gap-2"
                        >
                            <i className="bi bi-github"></i>
                            mihai209(github.com/mihai209)
                        </a>
                    </div>
                </div>
            </footer>
        </div>
    );
}
