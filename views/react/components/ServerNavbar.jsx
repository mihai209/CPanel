import React, { useState } from 'react';

const NAV_ICONS = {
    console:    'bi-terminal-fill',
    overview:   'bi-speedometer2',
    performance:  'bi-cpu-fill',
    smartalerts:  'bi-bell-fill',
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
    mounts:     'bi-hdd-stack-fill',
    scaling:    'bi-graph-up-arrow',
    policy:     'bi-shield-lock-fill',
    metrics:    'bi-bar-chart-fill',
    debuglogs:  'bi-bug-fill',
    auditconsole:'bi-shield-shaded',
    recovery:    'bi-life-preserver',
    ai:          'bi-robot',
    'proxy-network': 'bi-hdd-network-fill',
    macros:      'bi-command',
};

// Nav groups — order matters for display
const NAV_GROUPS = [
    { label: 'Server',    keys: ['console', 'overview', 'activity'] },
    { label: 'Storage',   keys: ['files', 'backups', 'dbs'] },
    { label: 'Access',    keys: ['network', 'users', 'api', 'schedules'] },
    { label: 'Config',    keys: ['startup', 'timeline', 'mounts', 'scaling', 'policy', 'macros'] },
    { label: 'Diagnostics', keys: ['metrics', 'debuglogs', 'auditconsole', 'performance', 'smartalerts', 'recovery', 'ai', 'proxy-network'] },
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
                'relative flex items-center gap-2.5 px-4 h-full text-[12.5px] font-black uppercase tracking-widest',
                'whitespace-nowrap border-b-2 transition-all duration-150 select-none',
                isDisabled
                    ? 'text-neutral-700 border-transparent cursor-not-allowed opacity-60'
                    : item.active
                        ? 'text-primary-400 border-primary-500 bg-primary-500/5'
                        : 'text-neutral-500 border-transparent hover:text-neutral-200 hover:border-neutral-500',
            ].join(' ')}
        >
            {icon && <i className={`bi ${icon} text-[16px] shrink-0`}></i>}
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
            <nav className="hidden md:flex bg-neutral-900 border-b border-neutral-800 w-full h-14 items-center px-6 lg:px-10 overflow-x-auto no-scrollbar gap-1.5">
                {activeGroups.map((group, gIdx) => (
                    <React.Fragment key={group.label}>
                        {/* Group separator */}
                        {gIdx > 0 && (
                            <div className="h-6 w-px bg-neutral-700/60 mx-1 shrink-0"></div>
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
                        <span className="text-[11px] font-black text-neutral-500 uppercase tracking-widest max-w-[180px] truncate">
                            {pageData.server.name}
                        </span>
                    </div>
                )}
            </nav>

            {/* ── Mobile Scrolling Bar ──────────────────────────────────── */}
            <div className="md:hidden bg-neutral-900 border-b border-neutral-800 w-full h-12 flex items-center px-4 overflow-x-auto no-scrollbar gap-1 relative">
                {activeGroups.map((group, gIdx) => (
                    <React.Fragment key={group.label}>
                        {/* Tiny separator between groups */}
                        {gIdx > 0 && (
                            <div className="h-4 w-px bg-neutral-800 mx-1 shrink-0"></div>
                        )}
                        <div className="flex items-center h-full">
                            {group.items.map(item => {
                                const isDisabled = isProvisioning && blockedKeys.includes(item.key);
                                const icon = NAV_ICONS[item.key];
                                return (
                                    <a
                                        key={item.key}
                                        href={isDisabled ? '#' : item.href}
                                        onClick={isDisabled ? (e) => e.preventDefault() : undefined}
                                        className={[
                                            'relative flex items-center gap-2 px-3 h-full text-[10px] font-black uppercase tracking-widest',
                                            'whitespace-nowrap transition-all duration-150 select-none border-b-2',
                                            isDisabled
                                                ? 'text-neutral-700 border-transparent cursor-not-allowed opacity-60'
                                                : item.active
                                                    ? 'text-primary-400 border-primary-500 bg-primary-500/5'
                                                    : 'text-neutral-500 border-transparent hover:text-neutral-300',
                                        ].join(' ')}
                                    >
                                        {icon && <i className={`bi ${icon} text-[14px] shrink-0`}></i>}
                                        <span>{item.label}</span>
                                    </a>
                                );
                            })}
                        </div>
                    </React.Fragment>
                ))}
            </div>
        </>
    );
}
