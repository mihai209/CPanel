import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-databases';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ServerDatabasesPage({ pageData = data }) {
    const server = pageData.server || {};
    const hostsList = Array.isArray(pageData.hosts) ? pageData.hosts : [];
    const dbList = Array.isArray(pageData.databases) ? pageData.databases : [];
    const limit = Math.max(0, Number.parseInt(pageData.databaseLimit, 10) || 0);
    const used = dbList.length;
    const remaining = Math.max(0, limit - used);
    const canManage = Boolean(pageData.canManageDatabases);
    const canCreate = canManage && hostsList.length > 0 && remaining > 0;

    const [revealedPasswords, setRevealedPasswords] = useState({});

    const togglePassword = (idx) => {
        setRevealedPasswords((prev) => ({ ...prev, [idx]: !prev[idx] }));
    };

    const copyPassword = async (pass) => {
        try {
            await navigator.clipboard.writeText(pass);
            // Optionally could flash a success message
        } catch {
            // ignore
        }
    };

    const deleteDatabase = async (id, e) => {
        if (!window.confirm('Delete this database and its DB user from the host? This cannot be undone.')) {
            e.preventDefault();
        }
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Databases">
            <PageContentBlock title="Databases" description="Manage database instances for this server.">
                
                {(!hostsList.length) && (
                    <div className="bg-yellow-500/10 border-l-4 border-yellow-500 text-yellow-500 p-4 rounded-r-lg mb-6 shadow-sm">
                        <i className="bi bi-exclamation-triangle-fill me-2"></i>
                        No database host is configured on this server location. Ask an admin to add one.
                    </div>
                )}

                {(limit <= 0) && (
                    <div className="bg-blue-500/10 border-l-4 border-blue-500 text-blue-400 p-4 rounded-r-lg mb-6 shadow-sm">
                        <i className="bi bi-info-circle-fill me-2"></i>
                        This server has <strong>0 database slots</strong>. Increase database slots from the configuration panel before creating databases.
                    </div>
                )}

                <div className="flex gap-4 mb-6 pt-2">
                    <span className="px-3 py-1 bg-neutral-800 border border-neutral-700 text-neutral-300 rounded text-sm font-bold shadow-sm">
                        Used: {used} / {limit}
                    </span>
                    <span className={`px-3 py-1 border text-sm font-bold shadow-sm rounded ${remaining > 0 ? 'bg-green-500/10 border-green-500/30 text-green-400' : 'bg-red-500/10 border-red-500/30 text-red-500'}`}>
                        Remaining: {remaining}
                    </span>
                </div>

                <div className="bg-neutral-900 border border-neutral-700 rounded-lg p-5 mb-8 shadow-sm">
                    <div className="flex justify-between items-center mb-4">
                        <h2 className="text-lg font-bold text-neutral-100">Create Database</h2>
                        {!canManage && <span className="text-xs px-2 py-1 bg-neutral-800 border border-neutral-700 rounded text-neutral-400">Read Only</span>}
                    </div>

                    <form method="POST" action={`/server/${server.containerId}/databases/create`} className="flex flex-col md:flex-row gap-4" data-turbo="false">
                        <div className="flex-1 md:max-w-xs">
                            <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">Host</label>
                            <input 
                                type="text" 
                                className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-400 focus:outline-none" 
                                value="Auto selected by location policy" 
                                readOnly 
                            />
                        </div>
                        <div className="flex-1">
                            <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">Database Name <span className="text-neutral-500 lowercase ml-1">(Optional)</span></label>
                            <input 
                                type="text" 
                                name="databaseName" 
                                maxLength="64"
                                className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" 
                                placeholder="example_db" 
                                disabled={!canCreate}
                            />
                        </div>
                        <div className="flex items-end">
                            <button 
                                type="submit" 
                                className="bg-primary-600 hover:bg-primary-500 text-white text-sm font-bold px-6 py-2 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                                disabled={!canCreate}
                            >
                                Create Database
                            </button>
                        </div>
                    </form>
                    <div className="text-xs text-neutral-500 mt-4">
                        Username and password are generated automatically when a database is created.
                    </div>
                </div>

                <div className="bg-neutral-900 border border-neutral-700 rounded-lg overflow-hidden shadow-sm">
                    <div className="bg-neutral-800/50 px-5 py-4 border-b border-neutral-700 flex justify-between items-center">
                        <h2 className="text-base font-bold text-neutral-100">Provisioned Databases</h2>
                        <span className="text-sm font-bold text-neutral-400">{dbList.length} Items</span>
                    </div>

                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-neutral-800 border-b border-neutral-700">
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">Host</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">Database</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">User</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest w-64">Password</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">Created</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {dbList.length === 0 ? (
                                    <tr>
                                        <td colSpan="6" className="text-center py-8 text-neutral-500 text-sm">No databases created yet.</td>
                                    </tr>
                                ) : (
                                    dbList.map((entry, idx) => (
                                        <tr key={entry.id} className="border-b border-neutral-700/50 hover:bg-neutral-800/30 transition-colors">
                                            <td className="px-5 py-4">
                                                <div className="font-bold text-neutral-200 text-sm">{entry.host ? entry.host.name : 'Unknown host'}</div>
                                                <div className="text-xs text-neutral-500 mt-1">{entry.host ? `${entry.host.host}:${entry.host.port}` : '-'}</div>
                                            </td>
                                            <td className="px-5 py-4">
                                                <span className="px-2 py-1 bg-primary-600/10 text-primary-400 border border-primary-600/20 rounded text-xs font-bold shadow-sm">{entry.name}</span>
                                            </td>
                                            <td className="px-5 py-4">
                                                <code className="text-xs text-green-400 bg-neutral-900 border border-neutral-700 px-2 py-1 rounded shadow-sm">{entry.username}</code>
                                            </td>
                                            <td className="px-5 py-4">
                                                <div className="flex bg-neutral-900 border border-neutral-700 rounded overflow-hidden shadow-sm">
                                                    <input 
                                                        type={revealedPasswords[idx] ? "text" : "password"} 
                                                        className="w-full bg-transparent border-none px-2 py-1 text-xs text-neutral-300 focus:outline-none" 
                                                        value={entry.password} 
                                                        readOnly 
                                                    />
                                                    <button 
                                                        type="button" 
                                                        className="px-2 py-1 text-neutral-400 hover:text-white hover:bg-neutral-700 transition" 
                                                        onClick={() => togglePassword(idx)}
                                                    >
                                                        <i className={`bi ${revealedPasswords[idx] ? 'bi-eye-slash' : 'bi-eye'}`}></i>
                                                    </button>
                                                    <button 
                                                        type="button" 
                                                        className="px-2 py-1 text-primary-400 hover:text-primary-300 hover:bg-primary-900/50 transition border-l border-neutral-700" 
                                                        onClick={() => copyPassword(entry.password)}
                                                    >
                                                        <i className="bi bi-clipboard"></i>
                                                    </button>
                                                </div>
                                            </td>
                                            <td className="px-5 py-4 text-xs text-neutral-500 whitespace-nowrap">
                                                {new Date(entry.createdAt).toLocaleString()}
                                            </td>
                                            <td className="px-5 py-4 flex items-center justify-end gap-2">
                                                <a href={`/server/${server.containerId}/database/${encodeURIComponent(entry.name)}`} className="text-neutral-400 hover:text-primary-400 transition" title="Open Database Manager">
                                                    <i className="bi bi-box-arrow-up-right"></i>
                                                </a>
                                                {canManage && (
                                                    <>
                                                        <form method="POST" action={`/server/${server.containerId}/databases/${entry.id}/password`} data-turbo="false">
                                                            <button type="submit" className="text-yellow-500 hover:text-yellow-400 transition" title="Rotate Password"><i className="bi bi-key"></i></button>
                                                        </form>
                                                        <form method="POST" action={`/server/${server.containerId}/databases/${entry.id}/delete`} onClick={(e) => deleteDatabase(entry.id, e)} data-turbo="false">
                                                            <button type="submit" className="text-red-500 hover:text-red-400 transition" title="Delete Database"><i className="bi bi-trash"></i></button>
                                                        </form>
                                                    </>
                                                )}
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerDatabasesPage;

if (root) {
    root.render(<ServerDatabasesPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
