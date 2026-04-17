import React from 'react';
import { NavLink } from 'react-router-dom';
import { ReactRoutes, resolveBrandImage, resolveUserAvatar } from '../ReactRoutes.js';

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
    return (
        <NavLink 
            to={to} 
            className={({ isActive }) => `px-4 py-3 text-sm font-semibold transition-colors ${isActive ? 'text-white border-b-2 border-primary-500' : 'text-neutral-400 hover:text-white'}`}
        >
            {label}
        </NavLink>
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

            {/* Server Deep Navigation (if in server view) */}
            {serverNavItems.length > 0 && (
                <nav className="bg-neutral-800/50 border-b border-neutral-700 flex overflow-x-auto px-4 lg:px-8">
                    {serverNavItems.map((item) => (
                        <a 
                            key={item.href} 
                            href={item.href} 
                            className={`px-4 py-3 text-sm font-semibold whitespace-nowrap transition-colors border-b-2 ${item.active ? 'text-white border-primary-500' : 'text-neutral-400 border-transparent hover:text-white hover:border-neutral-500'}`}
                        >
                            {item.label}
                        </a>
                    ))}
                </nav>
            )}

            {/* Main Content Area */}
            <main className="flex-1 w-full bg-neutral-900">
                {children}
            </main>
        </div>
    );
}
