import React, { useState } from 'react';

const NAV_ICONS = {
    console:    'bi-terminal-fill',
    overview:   'bi-speedometer2',
    activity:   'bi-clock-history',
    timeline:   'bi-list-ul',
    files:      'bi-folder2-open',
    backups:    'bi-cloud-arrow-down',
    dbs:        'bi-database',
    network:    'bi-diagram-3',
    users:      'bi-people-fill',
    api:        'bi-key-fill',
    schedules:  'bi-calendar-event',
    startup:    'bi-play-circle',
    mccenter:   'bi-controller',
    mcinstaller:'bi-download',
};

// Nav groups — order matters for display
const NAV_GROUPS = [
    { label: 'Server',    keys: ['console', 'overview', 'activity'] },
    { label: 'Storage',   keys: ['files', 'backups', 'dbs'] },
    { label: 'Access',    keys: ['network', 'users', 'api', 'schedules'] },
    { label: 'Config',    keys: ['startup', 'timeline'] },
    { label: 'Minecraft', keys: ['mccenter', 'mcinstaller'] },
];

function NavItem({ item, isProvisioning, blockedKeys }) {
    const isDisabled = isProvisioning && blockedKeys.includes(item.key);
    const icon = NAV_ICONS[item.key];

    return (
        <a
            href={isDisabled ? '#' : item.href}
            onClick={isDisabled ? (e) => e.preventDefault() : undefined}
            title={isDisabled ? `${item.label} — unavailable while server is provisioning` : item.label}
            className={[
                'relative flex items-center gap-2 px-3 h-full text-[11px] font-black uppercase tracking-widest',
                'whitespace-nowrap border-b-2 transition-all duration-150 select-none',
                isDisabled
                    ? 'text-neutral-700 border-transparent cursor-not-allowed opacity-60'
                    : item.active
                        ? 'text-primary-400 border-primary-500 bg-primary-500/5'
                        : 'text-neutral-500 border-transparent hover:text-neutral-200 hover:border-neutral-500',
            ].join(' ')}
        >
            {icon && <i className={`bi ${icon} text-[13px] shrink-0`}></i>}
            <span>{item.label}</span>
            {isDisabled && <i className="bi bi-lock-fill text-[8px] opacity-50 ml-0.5"></i>}
        </a>
    );
}

/**
 * ServerNavbar
 * 
 * Renders the horizontal secondary navigation bar for all /server/:id/* pages.
 * Pass `pageData` from any server route — it reads `serverNavItems`, `server.status`, and `server.containerId`.
 * 
 * @param {object} pageData  — full react page data object
 */
export default function ServerNavbar({ pageData = {} }) {
    const items = Array.isArray(pageData.serverNavItems) ? pageData.serverNavItems : [];
    if (items.length === 0) return null;

    const status = pageData.server?.status || '';
    const isProvisioning = ['installing', 'reinstalling'].includes(status);
    const blockedKeys = ['files', 'backups', 'dbs', 'network', 'users', 'api', 'schedules', 'startup', 'timeline'];

    const [mobileOpen, setMobileOpen] = useState(false);

    // Build ordered groups, skip empty ones
    const activeGroups = NAV_GROUPS.map(group => ({
        ...group,
        items: group.keys.map(k => items.find(i => i.key === k)).filter(Boolean),
    })).filter(g => g.items.length > 0);

    const activeItem = items.find(i => i.active);

    return (
        <>
            {/* ── Desktop Tab Bar ─────────────────────────────────────── */}
            <nav className="hidden md:flex bg-neutral-900/80 backdrop-blur-sm border-b border-neutral-800 w-full h-11 items-center px-4 lg:px-8 overflow-x-auto no-scrollbar gap-1">
                {activeGroups.map((group, gIdx) => (
                    <React.Fragment key={group.label}>
                        {/* Group separator */}
                        {gIdx > 0 && (
                            <div className="h-4 w-px bg-neutral-700/60 mx-0.5 shrink-0"></div>
                        )}
                        <div className="flex items-center h-full">
                            {group.items.map(item => (
                                <NavItem
                                    key={item.key}
                                    item={item}
                                    isProvisioning={isProvisioning}
                                    blockedKeys={blockedKeys}
                                />
                            ))}
                        </div>
                    </React.Fragment>
                ))}

                {/* Server name pill on the right */}
                {pageData.server?.name && (
                    <div className="ml-auto pl-4 shrink-0 flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full shrink-0 ${
                            status === 'running' ? 'bg-green-500' :
                            status === 'starting' ? 'bg-yellow-500 animate-pulse' :
                            status === 'stopping' ? 'bg-orange-500 animate-pulse' :
                            isProvisioning ? 'bg-blue-500 animate-pulse' :
                            'bg-neutral-600'
                        }`}></span>
                        <span className="text-[10px] font-black text-neutral-500 uppercase tracking-widest max-w-[140px] truncate">
                            {pageData.server.name}
                        </span>
                    </div>
                )}
            </nav>

            {/* ── Mobile Compact Bar ──────────────────────────────────── */}
            <div className="md:hidden bg-neutral-900/90 border-b border-neutral-800">
                {/* Current page indicator + toggle */}
                <button
                    onClick={() => setMobileOpen(v => !v)}
                    className="w-full flex items-center justify-between px-4 py-3"
                >
                    <div className="flex items-center gap-2">
                        {activeItem && NAV_ICONS[activeItem.key] && (
                            <i className={`bi ${NAV_ICONS[activeItem.key]} text-primary-400`}></i>
                        )}
                        <span className="text-sm font-bold text-neutral-200">
                            {activeItem?.label || 'Menu'}
                        </span>
                    </div>
                    <i className={`bi ${mobileOpen ? 'bi-chevron-up' : 'bi-chevron-down'} text-neutral-500 text-sm`}></i>
                </button>

                {/* Dropdown drawer */}
                {mobileOpen && (
                    <div className="border-t border-neutral-800 pb-2">
                        {activeGroups.map((group) => (
                            <div key={group.label}>
                                <div className="px-4 pt-3 pb-1 text-[9px] font-black text-neutral-600 uppercase tracking-widest">
                                    {group.label}
                                </div>
                                {group.items.map(item => {
                                    const isDisabled = isProvisioning && blockedKeys.includes(item.key);
                                    const icon = NAV_ICONS[item.key];
                                    return (
                                        <a
                                            key={item.key}
                                            href={isDisabled ? '#' : item.href}
                                            onClick={e => { if (isDisabled) e.preventDefault(); else setMobileOpen(false); }}
                                            className={[
                                                'flex items-center gap-3 px-5 py-2.5 text-sm font-semibold transition-colors',
                                                isDisabled
                                                    ? 'text-neutral-700 cursor-not-allowed'
                                                    : item.active
                                                        ? 'text-primary-400 bg-primary-500/5 border-l-2 border-primary-500 pl-[18px]'
                                                        : 'text-neutral-400 hover:text-white hover:bg-neutral-800/50',
                                            ].join(' ')}
                                        >
                                            {icon && <i className={`bi ${icon} text-base shrink-0`}></i>}
                                            <span>{item.label}</span>
                                            {isDisabled && <i className="bi bi-lock-fill text-xs opacity-40 ml-auto"></i>}
                                        </a>
                                    );
                                })}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </>
    );
}
