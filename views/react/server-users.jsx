import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-users';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

// Extracted descriptions mapped directly from legacy implementation
const userPermissionDescriptions = {
    'server.view': 'Access the server overview and basic details.',
    'server.tags.manage': 'Edit server folder and tags on overview.',
    'server.console': 'View the console and send commands.',
    'server.power': 'Start, stop, restart, or kill the server.',
    'server.files': 'View and edit server files.',
    'server.startup': 'Change startup command and variables.',
    'server.minecraft': 'Access Minecraft tools (mods/plugins).',
    'server.proxy.manage': 'Manage proxy network panel, backends, groups, and sync.',
    'server.ai.use': 'Use Rocky AI assistant in console.',
    'server.ai.manage': 'Manage Rocky AI permissions for this server.',
    'minecraft.inspect': 'Inspect player inventory, health, gamemode, location.',
    'minecraft.freeze': 'Freeze/unfreeze players using effects.',
    'minecraft.kick': 'Kick players from the Minecraft server.',
    'minecraft.ban': 'Ban players from the Minecraft server.',
    'minecraft.banlist': 'View banlist and unban players.',
    'minecraft.op': 'Grant operator rights with /op.',
    'minecraft.deop': 'Remove operator rights with /deop.',
    'minecraft.tempban': 'Temporarily ban players from the Minecraft server.',
    'minecraft.teleport': 'Teleport players with /tp.',
    'minecraft.chat': 'Control slow chat or mute chat server-wide.',
    'minecraft.whitelist': 'Manage server whitelist (add/remove/import).',
    'server.backups.view': 'View backups list.',
    'server.backups.manage': 'Create/delete backups (if enabled).',
    'server.gdrive': 'Use Google Drive backup actions (manual/auto policy).',
    'server.databases.view': 'View databases linked to the server.',
    'server.databases.manage': 'Create/update/delete databases.',
    'server.schedules.view': 'View schedules.',
    'server.schedules.manage': 'Create/update/delete schedules.',
    'server.network.view': 'View allocations and ports.',
    'server.network.manage': 'Manage allocations/ports.',
    'server.mounts': 'Attach/detach mounts.',
    'server.users.view': 'View subusers list.',
    'server.users.manage': 'Invite/remove subusers and edit permissions.',
    'server.activity.view': 'View activity logs.',
    'server.audit.read': 'Read audit console events (read-only).',
    'server.timeline.view': 'View live resource timeline.',
    'server.performance.view': 'View performance insights (plugins/mods).',
    'server.macros': 'Manage and run command macros.',
    'server.recovery': 'Use recovery assistant actions.',
    'server.smartalerts': 'Configure smart alerts.',
    'server.policy': 'Configure policy engine.'
};

export function ServerUsersPage({ pageData = data }) {
    const server = pageData.server || {};
    const memberships = Array.isArray(pageData.memberships) ? pageData.memberships : [];
    const owner = pageData.owner || null;
    const canManageUsers = Boolean(pageData.canManageUsers);
    
    // Modal state block
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [editingMembership, setEditingMembership] = useState(null); // null = create mode
    const [identifier, setIdentifier] = useState('');
    const [selectedPermissions, setSelectedPermissions] = useState(['server.view']);
    const [selectedPreset, setSelectedPreset] = useState('');

    const presets = pageData.permissionPresets || [];
    const catalog = pageData.permissionCatalog || [];

    const handleOpenCreate = () => {
        setEditingMembership(null);
        setIdentifier('');
        setSelectedPermissions(['server.view']);
        setSelectedPreset('');
        setIsModalOpen(true);
    };

    const handleOpenEdit = (membership) => {
        setEditingMembership(membership);
        setIdentifier(membership.user?.email || membership.user?.username || '');
        const perms = Array.isArray(membership.permissions) && membership.permissions.length > 0 
            ? membership.permissions 
            : ['server.view'];
        setSelectedPermissions(perms);
        
        // Match preset if possible
        const sortedSelected = [...perms].sort();
        const matchedPreset = presets.find(p => {
            const presetPerms = [...p.permissions].sort();
            return presetPerms.length === sortedSelected.length && presetPerms.every((v, i) => v === sortedSelected[i]);
        });
        setSelectedPreset(matchedPreset ? matchedPreset.id : '');
        
        setIsModalOpen(true);
    };

    const handleTogglePerm = (perm) => {
        if (perm === 'server.view') return; // Enforced toggle lock for standard pterodactyl
        setSelectedPermissions(current => 
            current.includes(perm) ? current.filter(p => p !== perm) : [...current, perm]
        );
        setSelectedPreset(''); // User made a custom change
    };

    const applyPreset = () => {
        if (!selectedPreset) return;
        const preset = presets.find(p => String(p.id) === String(selectedPreset));
        if (preset) {
            setSelectedPermissions(Array.from(new Set([...preset.permissions, 'server.view'])));
        }
    };

    const resetPermissions = () => {
        setSelectedPermissions(['server.view']);
        setSelectedPreset('');
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Users">
            <PageContentBlock title="Users" description="Manage subusers and configure access control lists.">

                {pageData.success && (
                    <div className="bg-green-600/20 border-l-4 border-green-600 text-green-100 p-4 rounded-r-lg mb-6 shadow-sm">
                        {pageData.success}
                    </div>
                )}
                {pageData.error && (
                    <div className="bg-red-600/20 border-l-4 border-red-600 text-red-100 p-4 rounded-r-lg mb-6 shadow-sm">
                        {pageData.error}
                    </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                    {/* Owner Card */}
                    <div className="bg-neutral-900 border border-neutral-700 rounded-lg p-5 shadow-sm col-span-1 border-t-2 border-t-primary-500">
                        <div className="text-xs font-bold text-neutral-500 uppercase tracking-widest mb-3">Owner</div>
                        <div className="font-bold text-white text-lg">{owner ? owner.username : 'Unknown'}</div>
                        <div className="text-sm text-neutral-400 mt-1">{owner ? owner.email : '-'}</div>
                    </div>
                </div>

                {/* Subusers List */}
                <div className="bg-neutral-900 border border-neutral-700 rounded-lg overflow-hidden shadow-sm">
                    <div className="bg-neutral-800/50 px-5 py-4 border-b border-neutral-700 flex justify-between items-center">
                        <h2 className="text-base font-bold text-neutral-100">Subusers</h2>
                        {canManageUsers && (
                            <button 
                                onClick={handleOpenCreate}
                                className="bg-primary-600 hover:bg-primary-500 text-white text-xs font-bold px-3 py-1.5 rounded transition-colors shadow-sm"
                            >
                                <i className="bi bi-person-plus me-1"></i> Invite
                            </button>
                        )}
                    </div>

                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-neutral-800 border-b border-neutral-700">
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">User</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">Permissions</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">Invited By</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {!memberships.length ? (
                                    <tr><td colSpan="4" className="text-center py-8 text-neutral-500 text-sm">No subusers yet.</td></tr>
                                ) : memberships.map(entry => (
                                    <tr key={entry.id} className="border-b border-neutral-700/50 hover:bg-neutral-800/30 transition-colors">
                                        <td className="px-5 py-4">
                                            <div className="font-bold text-neutral-200 text-sm">{entry.user ? entry.user.username : `#${entry.userId}`}</div>
                                            <div className="text-xs text-neutral-500">{entry.user?.email || ''}</div>
                                        </td>
                                        <td className="px-5 py-4">
                                            <code className="text-xs text-primary-300 bg-neutral-900 border border-neutral-700 px-2 py-1 rounded shadow-sm break-all">
                                                {Array.isArray(entry.permissions) ? entry.permissions.join(', ') : ''}
                                            </code>
                                        </td>
                                        <td className="px-5 py-4 text-sm text-neutral-400">
                                            {entry.invitedBy ? entry.invitedBy.username : '-'}
                                        </td>
                                        <td className="px-5 py-4 text-right">
                                            {canManageUsers ? (
                                                <button 
                                                    onClick={() => handleOpenEdit(entry)}
                                                    className="bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-white text-xs font-bold px-3 py-1.5 rounded transition-colors shadow-sm"
                                                >
                                                    Manage
                                                </button>
                                            ) : (
                                                <span className="text-neutral-500">-</span>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>

            </PageContentBlock>

            {/* Modal Overlay Mapping */}
            {isModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-neutral-900/80 backdrop-blur-sm overflow-y-auto">
                    <div className="bg-neutral-900 border border-neutral-700 rounded-xl shadow-2xl w-full max-w-3xl my-8">
                        <div className="flex justify-between items-center p-5 border-b border-neutral-700">
                            <h3 className="text-lg font-bold text-white">
                                {editingMembership ? `Manage ${editingMembership.user?.username || 'Subuser'}` : 'Invite Subuser'}
                            </h3>
                            <button onClick={() => setIsModalOpen(false)} className="text-neutral-400 hover:text-white transition">
                                <i className="bi bi-x-lg"></i>
                            </button>
                        </div>
                        
                        <div className="p-5 overflow-y-auto max-h-[70vh]">
                            <form id="subuserForm" method="POST" action={`/server/${server.containerId}/users`} data-turbo="false">
                                <input type="hidden" name="membershipId" value={editingMembership ? editingMembership.id : ''} />
                                
                                <div className="mb-6">
                                    <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">User Identifier</label>
                                    <input 
                                        name="identifier" 
                                        className={`w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-primary-500 ${editingMembership ? 'opacity-50 cursor-not-allowed' : ''}`}
                                        placeholder="Username or email"
                                        value={identifier}
                                        onChange={(e) => setIdentifier(e.target.value)}
                                        readOnly={!!editingMembership}
                                    />
                                </div>

                                <div className="mb-4">
                                    <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">Permissions</label>
                                    
                                    <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-3 mb-4 flex flex-col md:flex-row gap-3 items-end">
                                        <div className="flex-1 w-full">
                                            <label className="block text-xs font-bold text-neutral-500 uppercase tracking-widest mb-1">Preset Bundle</label>
                                            <select 
                                                className="w-full bg-neutral-900 border border-neutral-700 rounded px-3 py-2 text-sm text-white focus:outline-none"
                                                value={selectedPreset}
                                                onChange={(e) => setSelectedPreset(e.target.value)}
                                            >
                                                <option value="">Custom Selection</option>
                                                {presets.map(p => (
                                                    <option key={p.id} value={p.id}>{p.label}</option>
                                                ))}
                                            </select>
                                        </div>
                                        <div className="flex gap-2 w-full md:w-auto">
                                            <button type="button" onClick={applyPreset} className="bg-primary-600/20 text-primary-400 border border-primary-600/30 hover:bg-primary-600/30 rounded px-4 py-2 text-sm font-bold transition flex-1 md:flex-none">
                                                <i className="bi bi-magic me-1"></i> Apply Preset
                                            </button>
                                            <button type="button" onClick={resetPermissions} className="bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 rounded px-4 py-2 text-sm font-bold text-white transition flex-1 md:flex-none">
                                                Reset
                                            </button>
                                        </div>
                                    </div>

                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                        {catalog.map(perm => (
                                            <label key={perm} className="flex items-start gap-3 p-3 bg-neutral-800/50 border border-neutral-700 rounded-lg cursor-pointer hover:bg-neutral-800 transition-colors">
                                                <input 
                                                    type="checkbox" 
                                                    name="permissions"
                                                    value={perm}
                                                    checked={selectedPermissions.includes(perm)}
                                                    onChange={() => handleTogglePerm(perm)}
                                                    disabled={perm === 'server.view'}
                                                    className="mt-0.5 bg-neutral-900 border-neutral-600 text-primary-500 focus:ring-0 rounded"
                                                />
                                                <div>
                                                    <div className="text-sm font-bold text-white">{perm}</div>
                                                    <div className="text-xs text-neutral-500 mt-0.5 whitespace-normal break-words">{userPermissionDescriptions[perm] || 'Access standard endpoints'}</div>
                                                </div>
                                            </label>
                                        ))}
                                    </div>
                                </div>
                            </form>
                        </div>
                        
                        <div className="flex items-center justify-between p-5 border-t border-neutral-700 bg-neutral-900 rounded-b-xl">
                            {editingMembership ? (
                                <form method="POST" action={`/server/${server.containerId}/users/${editingMembership.id}/delete`} data-turbo="false">
                                    <button type="submit" className="text-red-500 hover:text-red-400 text-sm font-bold transition">
                                        Remove Subuser
                                    </button>
                                </form>
                            ) : <div></div>}
                            
                            <div className="flex gap-3">
                                <button onClick={() => setIsModalOpen(false)} className="px-4 py-2 bg-neutral-800 hover:bg-neutral-700 text-white rounded text-sm font-bold">
                                    Cancel
                                </button>
                                <button 
                                    onClick={() => document.getElementById('subuserForm').submit()} 
                                    className="px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded text-sm font-bold shadow-sm"
                                >
                                    {editingMembership ? 'Update Subuser' : 'Save Subuser'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </ReactAppShell>
    );
}

export default ServerUsersPage;

if (root) {
    root.render(<ServerUsersPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
