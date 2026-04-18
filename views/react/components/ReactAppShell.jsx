import React from 'react';
import { useLocation } from 'react-router-dom';
import { ReactRoutes, resolveBrandImage, resolveUserAvatar } from '../ReactRoutes.js';
import ProvisioningBarrier from './ProvisioningBarrier.jsx';
import GlobalStatusModal from './GlobalStatusModal.jsx';
import NotificationBell from './NotificationBell.jsx';
import GlobalSearch from './GlobalSearch.jsx';
import ServerNavbar from './ServerNavbar.jsx';
import SponsorModal from './SponsorModal.jsx';
import FooterLegalModal from './FooterLegalModal.jsx';
// Layout components

// Import base themes
import '../../../public/css/react-themes-base.css';

function InternalTopAction({ to, icon, title }) {
    const location = useLocation();
    const isActive = location.pathname === to;
    return (
        <a
            href={to}
            title={title}
            className={`text-neutral-400 hover:text-neutral-100 transition-colors p-2 rounded-full hover:bg-neutral-700 ${isActive ? 'text-neutral-100 bg-neutral-700' : ''}`}
        >
            <i className={`bi ${icon}`}></i>
        </a>
    );
}

function PrimaryNavLink({ to, label }) {
    const location = useLocation();
    const isActive = to === '/' ? location.pathname === '/' : location.pathname.startsWith(to);
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
    const [sponsorModalOpen, setSponsorModalOpen] = React.useState(false);
    const [legalModalOpen, setLegalModalOpen] = React.useState(false);
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
        <div 
            className={`min-h-screen text-neutral-200 flex flex-col transition-all duration-700 ${pageClassName || ''}`}
            style={{ 
                background: 'transparent'
            }}
        >
            
            {/* Top Navigation Bar */}
            <div className="bg-neutral-800 border-b border-neutral-700 w-full flex items-center justify-between px-4 lg:px-8 h-16 shrink-0 sticky top-0 z-40 shadow-md">
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
                        <InternalTopAction to={ReactRoutes.themes} icon="bi-palette-fill" title="Themes" />
                        <InternalTopAction to={ReactRoutes.rewards} icon="bi-coin" title="Rewards" />
                        <InternalTopAction to={ReactRoutes.afk} icon="bi-hourglass-split" title="AFK Timer" />
                        <NotificationBell />
                        <div className="h-6 w-px bg-neutral-700 mx-2"></div>
                        <InternalTopAction to={ReactRoutes.outdatedFeatures} icon="bi-sliders" title="Outdated Features" />
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
        <div className="md:hidden bg-neutral-800 border-b border-neutral-700 flex flex-col py-2">
            {shellNavItems.map((item) => {
                const isActive = item.to === '/' ? window.location.pathname === '/' : window.location.pathname.startsWith(item.to);
                return (
                    <a 
                        key={item.to} 
                        href={item.to} 
                        className={`px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${isActive ? 'text-primary-400 bg-primary-500/5' : 'text-neutral-400 hover:text-white'}`}
                    >
                        <i className={`bi ${item.to === ReactRoutes.dashboard ? 'bi-grid-fill' : 'bi-person-fill'} text-lg`}></i>
                        {item.label}
                    </a>
                );
            })}
            <div className="h-px bg-neutral-700/50 mx-5 my-1"></div>
            <a href={ReactRoutes.themes} className={`px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${window.location.pathname === ReactRoutes.themes ? 'text-primary-400 bg-primary-500/5' : 'text-neutral-400 hover:text-white'}`}>
                <i className="bi bi-palette-fill text-lg"></i>
                Themes
            </a>
            <a href={ReactRoutes.rewards} className={`px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${window.location.pathname === ReactRoutes.rewards ? 'text-primary-400 bg-primary-500/5' : 'text-neutral-400 hover:text-white'}`}>
                <i className="bi bi-coin text-lg"></i>
                Rewards
            </a>
            <a href={ReactRoutes.afk} className={`px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${window.location.pathname === ReactRoutes.afk ? 'text-primary-400 bg-primary-500/5' : 'text-neutral-400 hover:text-white'}`}>
                <i className="bi bi-hourglass-split text-lg"></i>
                AFK Timer
            </a>
            
            <div className="h-px bg-neutral-700/50 mx-5 my-1"></div>
            <a href={ReactRoutes.outdatedFeatures} className={`px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${window.location.pathname === ReactRoutes.outdatedFeatures ? 'text-primary-400 bg-primary-500/5' : 'text-neutral-400 hover:text-white'}`}>
                <i className="bi bi-sliders text-lg"></i>
                Outdated Features
            </a>
            {pageData.user?.isAdmin && (
                <>
                    <a href={ReactRoutes.admin} className="px-5 py-3 text-sm font-bold flex items-center gap-3 text-neutral-400 hover:text-white transition-colors">
                        <i className="bi bi-gear-fill text-lg"></i>
                        Admin Panel
                    </a>
                    <a href={ReactRoutes.connectorsCheck} className={`px-5 py-3 text-sm font-bold flex items-center gap-3 transition-colors ${window.location.pathname === ReactRoutes.connectorsCheck ? 'text-primary-400 bg-primary-500/5' : 'text-neutral-400 hover:text-white'}`}>
                        <i className="bi bi-cpu text-lg"></i>
                        Connectors Check
                    </a>
                    <div className="h-px bg-neutral-700/50 mx-5 my-1"></div>
                </>
            )}

            <a href={ReactRoutes.changeView} className="px-5 py-3 text-sm font-bold flex items-center gap-3 text-neutral-400 hover:text-white transition-colors">
                <i className="bi bi-door-open text-lg"></i>
                Exit Beta Mode
            </a>
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
            <SponsorModal isOpen={sponsorModalOpen} onClose={() => setSponsorModalOpen(false)} />
            <FooterLegalModal isOpen={legalModalOpen} onClose={() => setLegalModalOpen(false)} />

            {/* Global Footer */}
            <footer className="w-full py-12 border-t border-neutral-800 bg-neutral-900 mt-auto overflow-hidden relative">
                <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-4xl h-px bg-gradient-to-r from-transparent via-neutral-700/50 to-transparent"></div>
                
                <div className="px-4 lg:px-8 max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-10">
                    <div className="flex flex-col items-center md:items-start gap-4">
                        <div className="flex items-center gap-4">
                            <img src={brandImage} alt="Brand" className="w-6 h-6 grayscale opacity-30" />
                            <span className="text-[10px] font-black text-neutral-500 uppercase tracking-[0.3em]">
                                CPanel Rocky &copy; 2026
                            </span>
                        </div>
                        <div className="flex items-center gap-2">
                            <a 
                                href="https://github.com/mihai209" 
                                target="_blank" 
                                rel="noopener noreferrer"
                                className="px-4 py-2 rounded-xl bg-neutral-800/50 hover:bg-neutral-800 text-[10px] font-bold text-neutral-500 hover:text-white transition-all border border-neutral-700/30 flex items-center gap-2"
                            >
                                <i className="bi bi-github"></i>
                                Mihai209
                            </a>
                            <a 
                                href="https://cpanel-rocky.netlify.app/" 
                                target="_blank" 
                                rel="noopener noreferrer"
                                className="px-4 py-2 rounded-xl bg-neutral-800/50 hover:bg-neutral-800 text-[10px] font-bold text-neutral-500 hover:text-white transition-all border border-neutral-700/30 flex items-center gap-2"
                            >
                                <i className="bi bi-globe"></i>
                                Project Website
                            </a>
                        </div>
                    </div>

                    <div className="flex items-center gap-3">
                        <button
                            onClick={() => setSponsorModalOpen(true)}
                            className="group flex items-center gap-3 px-6 py-3 rounded-2xl bg-primary-600/10 hover:bg-primary-600 text-primary-400 hover:text-white transition-all duration-300 border border-primary-500/20 active:scale-95"
                        >
                            <i className="bi bi-heart-fill animate-pulse group-hover:animate-none"></i>
                            <span className="text-[10px] font-black uppercase tracking-[0.2em]">Sponsor Project</span>
                        </button>

                        <button
                            onClick={() => setLegalModalOpen(true)}
                            className="p-3 rounded-2xl bg-neutral-800/50 hover:bg-neutral-800 text-neutral-500 hover:text-white transition-all border border-neutral-700/30 active:scale-95"
                            title="Licensing & Support Policy"
                        >
                            <i className="bi bi-info-circle-fill text-lg"></i>
                        </button>
                    </div>
                </div>
            </footer>
        </div>
    );
}
