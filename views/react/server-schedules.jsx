import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-schedules';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ServerSchedulesPage({ pageData = data }) {
    const server = pageData.server || {};
    const schedules = Array.isArray(pageData.schedules) ? pageData.schedules : [];
    const canManageSchedules = Boolean(pageData.canManageSchedules);
    const timezone = pageData.settings?.timezone || 'system default';

    const [isTutorialOpen, setIsTutorialOpen] = useState(false);

    return (
        <ReactAppShell pageData={pageData} subtitle="Schedules">
            <PageContentBlock title="Schedules" description="Automate server actions with cron-based tasks.">

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

                <div className="flex justify-end mb-4">
                    <button 
                        onClick={() => setIsTutorialOpen(true)}
                        className="bg-neutral-800 hover:bg-neutral-700 text-neutral-300 px-3 py-1.5 rounded text-sm font-bold transition-colors border border-neutral-700"
                    >
                        <i className="bi bi-question-circle me-1"></i> Tutorial
                    </button>
                </div>

                {canManageSchedules && (
                    <div className="bg-neutral-900 border border-neutral-700 rounded-lg p-5 mb-8 shadow-sm">
                        <h2 className="text-lg font-bold text-neutral-100 mb-4">Create Schedule</h2>
                        <form method="POST" action={`/server/${server.containerId}/schedules`} className="flex flex-col gap-4" data-turbo="false">
                            <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
                                <div className="md:col-span-3">
                                    <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-1.5">Name</label>
                                    <input type="text" name="name" required className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" />
                                </div>
                                <div className="md:col-span-2">
                                    <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-1.5">Action</label>
                                    <select name="action" className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500">
                                        <option value="command">Command</option>
                                        <option value="power">Power</option>
                                    </select>
                                </div>
                                <div className="md:col-span-2">
                                    <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-1.5">Cron</label>
                                    <input type="text" name="cron" defaultValue="* * * * *" className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 font-mono" />
                                </div>
                                <div className="md:col-span-3">
                                    <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-1.5">Payload</label>
                                    <input type="text" name="payload" placeholder="say hello / restart" className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 font-mono" />
                                </div>
                                <div className="md:col-span-2">
                                    <button type="submit" className="w-full bg-primary-600 hover:bg-primary-500 text-white text-sm font-bold px-4 py-2 rounded transition-colors shadow-sm">
                                        Save
                                    </button>
                                </div>
                            </div>
                            
                            <div className="flex flex-wrap gap-6 mt-2">
                                <label className="flex items-center gap-2 cursor-pointer">
                                    <input type="checkbox" name="enabled" value="1" defaultChecked className="bg-neutral-900 border-neutral-600 text-primary-500 focus:ring-0 rounded" />
                                    <span className="text-sm text-neutral-300 font-semibold">Enabled</span>
                                </label>
                                <label className="flex items-center gap-2 cursor-pointer">
                                    <input type="checkbox" name="onlyWhenOnline" value="1" className="bg-neutral-900 border-neutral-600 text-primary-500 focus:ring-0 rounded" />
                                    <span className="text-sm text-neutral-300 font-semibold">Run only when server is online</span>
                                </label>
                            </div>
                        </form>
                        <div className="text-xs text-neutral-500 mt-4 bg-neutral-800/50 p-3 rounded border border-neutral-700/50">
                            <strong>Note:</strong> Power payload accepts <code className="text-primary-400 mx-1">start|stop|restart|kill</code>. Command payload accepts any raw console text command.
                        </div>
                    </div>
                )}

                <div className="bg-neutral-900 border border-neutral-700 rounded-lg overflow-hidden shadow-sm">
                    <div className="bg-neutral-800/50 px-5 py-4 border-b border-neutral-700">
                        <h2 className="text-base font-bold text-neutral-100">Configured Schedules</h2>
                    </div>

                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-neutral-800 border-b border-neutral-700">
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">Name</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">Action</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">Cron</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">Payload</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">Status</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest">Last Run</th>
                                    <th className="px-5 py-3 text-xs font-bold text-neutral-400 uppercase tracking-widest text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {schedules.length === 0 ? (
                                    <tr>
                                        <td colSpan="7" className="text-center py-8 text-neutral-500 text-sm">No schedules configured.</td>
                                    </tr>
                                ) : (
                                    schedules.map(entry => (
                                        <tr key={entry.id} className="border-b border-neutral-700/50 hover:bg-neutral-800/30 transition-colors">
                                            <td className="px-5 py-4 text-sm font-bold text-white">{entry.name}</td>
                                            <td className="px-5 py-4">
                                                <span className="px-2 py-1 bg-primary-600/20 text-primary-400 border border-primary-600/30 rounded text-xs font-bold">
                                                    {entry.action}
                                                </span>
                                            </td>
                                            <td className="px-5 py-4">
                                                <code className="text-xs bg-neutral-900 border border-neutral-700 px-2 py-1 rounded text-neutral-300 font-mono">
                                                    {entry.cron || '-'}
                                                </code>
                                            </td>
                                            <td className="px-5 py-4">
                                                <code className="text-xs bg-neutral-900 border border-neutral-700 px-2 py-1 rounded text-neutral-300 font-mono break-all max-w-[200px] inline-block">
                                                    {entry.payload || '-'}
                                                </code>
                                            </td>
                                            <td className="px-5 py-4">
                                                <div className="flex gap-2">
                                                    <span className={`px-2 py-1 rounded text-xs font-bold ${entry.enabled === false ? 'bg-neutral-800 text-neutral-400' : 'bg-green-600/20 text-green-400 border border-green-600/30'}`}>
                                                        {entry.enabled === false ? 'Disabled' : 'Enabled'}
                                                    </span>
                                                    {entry.onlyWhenOnline && (
                                                        <span className="px-2 py-1 rounded text-xs font-bold bg-yellow-500/20 text-yellow-500 border border-yellow-500/30">
                                                            Online Only
                                                        </span>
                                                    )}
                                                </div>
                                            </td>
                                            <td className="px-5 py-4 text-xs text-neutral-400">
                                                {entry.lastRunAt ? new Date(entry.lastRunAt).toLocaleString() : 'Never'}
                                            </td>
                                            <td className="px-5 py-4 text-right">
                                                {canManageSchedules ? (
                                                    <div className="flex justify-end gap-2">
                                                        <form method="POST" action={`/server/${server.containerId}/schedules/${entry.id}/run`} data-turbo="false">
                                                            <button type="submit" className="text-green-500 hover:text-green-400 bg-neutral-900 border border-neutral-700 hover:bg-neutral-800 p-1.5 rounded transition">
                                                                <i className="bi bi-play-fill text-sm"></i>
                                                            </button>
                                                        </form>
                                                        <form method="POST" action={`/server/${server.containerId}/schedules/${entry.id}/delete`} data-turbo="false" onSubmit={(e) => {
                                                            if (!window.confirm('Delete this schedule?')) e.preventDefault();
                                                        }}>
                                                            <button type="submit" className="text-red-500 hover:text-red-400 bg-neutral-900 border border-neutral-700 hover:bg-neutral-800 p-1.5 rounded transition">
                                                                <i className="bi bi-trash text-sm"></i>
                                                            </button>
                                                        </form>
                                                    </div>
                                                ) : <span className="text-neutral-500">-</span>}
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

            </PageContentBlock>

            {/* Tutorial Modal */}
            {isTutorialOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-neutral-900/80 backdrop-blur-sm">
                    <div className="bg-neutral-900 border border-neutral-700 rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden">
                        <div className="flex justify-between items-center p-5 border-b border-neutral-700">
                            <h3 className="text-lg font-bold text-white">Schedules Tutorial</h3>
                            <button onClick={() => setIsTutorialOpen(false)} className="text-neutral-400 hover:text-white transition">
                                <i className="bi bi-x-lg"></i>
                            </button>
                        </div>
                        <div className="p-6 overflow-y-auto max-h-[70vh]">
                            <p className="text-neutral-400 mb-6 leading-relaxed">
                                Use schedules to execute commands automatically. Everything is processed according to the panel's timezone (<code className="bg-neutral-800 px-1 rounded text-primary-400">{timezone}</code>).
                            </p>

                            <h4 className="text-white font-bold mb-3 flex items-center gap-2">
                                <span className="bg-primary-600/20 text-primary-400 w-6 h-6 flex items-center justify-center rounded-full text-xs">1</span>
                                Core Fields
                            </h4>
                            <ul className="text-neutral-400 mb-6 space-y-2 ml-2 border-l-2 border-neutral-800 pl-4">
                                <li><strong>Name:</strong> Name of the task (e.g. <code className="bg-neutral-800 px-1 rounded">Auto Save</code>).</li>
                                <li><strong>Action:</strong> <code className="bg-neutral-800 px-1 rounded">command</code> or <code className="bg-neutral-800 px-1 rounded">power</code>.</li>
                                <li><strong>Cron:</strong> Format is <code className="bg-neutral-800 px-1 rounded">minute hour day month weekday</code>.</li>
                                <li><strong>Payload:</strong> The console command for `command` tasks, or <code className="bg-neutral-800 px-1 rounded">start|stop|restart|kill</code> for power.</li>
                            </ul>

                            <h4 className="text-white font-bold mb-3 flex items-center gap-2">
                                <span className="bg-primary-600/20 text-primary-400 w-6 h-6 flex items-center justify-center rounded-full text-xs">2</span>
                                Quick Examples
                            </h4>
                            
                            <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-4 mb-4">
                                <div className="text-sm font-bold text-white mb-2 pb-2 border-b border-neutral-700/50">Autosave every 5 minutes</div>
                                <pre className="text-sm text-primary-300 font-mono">
Name: Auto Save
Action: command
Cron: */5 * * * *
Payload: save-all
                                </pre>
                            </div>

                            <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-4 mb-6">
                                <div className="text-sm font-bold text-white mb-2 pb-2 border-b border-neutral-700/50">Daily Restart at 04:00</div>
                                <pre className="text-sm text-primary-300 font-mono">
Name: Daily Restart
Action: power
Cron: 0 4 * * *
Payload: restart
                                </pre>
                            </div>

                            <h4 className="text-white font-bold mb-3 flex items-center gap-2">
                                <span className="bg-primary-600/20 text-primary-400 w-6 h-6 flex items-center justify-center rounded-full text-xs">3</span>
                                Recommendations
                            </h4>
                            <ul className="text-neutral-400 mb-2 space-y-2 ml-2 border-l-2 border-neutral-800 pl-4">
                                <li>Check <em>Run only when server is online</em> for in-game commands that require the runtime to be active.</li>
                                <li>For critical tasks, click <strong>Run</strong> immediately after creation to test the payload directly.</li>
                            </ul>
                        </div>
                        <div className="p-4 border-t border-neutral-700 bg-neutral-800/50 flex justify-end">
                            <button onClick={() => setIsTutorialOpen(false)} className="px-5 py-2 bg-neutral-700 hover:bg-neutral-600 text-white rounded text-sm font-bold transition">
                                Got It
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </ReactAppShell>
    );
}

export default ServerSchedulesPage;

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <ServerSchedulesPage pageData={data} />
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}