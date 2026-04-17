import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-minecraft-world-center';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function WorldEntryRow({ world, isActive, serverId }) {
    return (
        <div className={`grid grid-cols-1 md:grid-cols-12 gap-4 items-center p-5 border-b border-neutral-800 last:border-0 transition-colors ${isActive ? 'bg-primary-600/5' : 'hover:bg-neutral-800/30'}`}>
            <div className="md:col-span-1 flex justify-center">
                <i className={`text-2xl ${world.isZip ? 'bi bi-file-earmark-zip text-amber-500' : 'bi bi-folder-fill text-primary-500'}`}></i>
            </div>
            <div className="md:col-span-5 flex flex-col min-w-0">
                <div className="flex items-center gap-2">
                    <span className="font-bold text-neutral-100 truncate">{world.name}</span>
                    {isActive && (
                        <span className="bg-primary-600 text-[9px] text-white px-2 py-0.5 rounded-full font-black uppercase tracking-widest shadow-lg shadow-primary-900/20">Active</span>
                    )}
                </div>
                <div className="text-[10px] text-neutral-500 uppercase font-black tracking-widest mt-1">
                    {world.isZip ? 'Archive' : 'Directory'} · {formatBytes(world.size)}
                </div>
            </div>
            <div className="md:col-span-2 flex items-center gap-2 overflow-x-auto no-scrollbar">
                {world.hasNether && <span className="text-[10px] bg-red-900/20 text-red-500 border border-red-900/30 px-2 py-0.5 rounded uppercase font-bold">Nether</span>}
                {world.hasEnd && <span className="text-[10px] bg-purple-900/20 text-purple-500 border border-purple-900/30 px-2 py-0.5 rounded uppercase font-bold">End</span>}
                {!world.hasNether && !world.hasEnd && !world.isZip && <span className="text-[10px] text-neutral-600 uppercase font-bold">Overworld Only</span>}
            </div>
            <div className="md:col-span-4 flex justify-end items-center gap-2">
                {!isActive && !world.isZip && (
                    <form action={`/server/${serverId}/minecraft/world-center/swap`} method="POST">
                        <input type="hidden" name="activeWorld" value={world.name} />
                        <button type="submit" className="px-4 py-2 bg-neutral-800 hover:bg-neutral-700 text-neutral-200 text-xs font-bold uppercase tracking-widest rounded border border-neutral-700 transition active:scale-95 shadow-lg">
                            Activate
                        </button>
                    </form>
                )}
                <div className="h-6 w-px bg-neutral-800 hidden md:block mx-1"></div>
                <button className="p-2 text-neutral-500 hover:text-white transition" title="Delete World (Not Implemented)">
                    <i className="bi bi-trash"></i>
                </button>
            </div>
        </div>
    );
}

export function ServerMinecraftWorldCenterPage({ pageData = data }) {
    const server = pageData.server || {};
    const worldData = pageData.worldData || { worlds: [], activeWorld: '' };
    const feedback = pageData.feedback || {};

    return (
        <ReactAppShell pageData={pageData} subtitle="World Center">
            <PageContentBlock 
                title="World Center" 
                description={`Switch between different regions and managing your world folders for ${server.name}.`}
                eyebrow="Game Management"
            >
                {feedback.error && (
                    <div className="mb-8 bg-rose-600/10 border border-rose-600/30 text-rose-400 p-4 rounded-2xl flex items-center gap-4 animate-in fade-in slide-in-from-top-4">
                        <i className="bi bi-exclamation-octagon text-xl"></i>
                        <span className="text-sm font-bold uppercase tracking-widest">{feedback.error}</span>
                    </div>
                )}
                {feedback.success && (
                    <div className="mb-8 bg-emerald-600/10 border border-emerald-600/30 text-emerald-400 p-4 rounded-2xl flex items-center gap-4 animate-in fade-in slide-in-from-top-4">
                        <i className="bi bi-check2-circle text-xl"></i>
                        <span className="text-sm font-bold uppercase tracking-widest">{feedback.success}</span>
                    </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
                    {/* Main World List */}
                    <div className="lg:col-span-3">
                        <div className="bg-neutral-900 border border-neutral-800 rounded-3xl overflow-hidden shadow-2xl">
                            <div className="px-6 py-5 bg-neutral-800/50 border-b border-neutral-800 flex items-center justify-between">
                                <h3 className="text-sm font-black text-white uppercase tracking-widest">Detected World Containers</h3>
                                <div className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest">
                                    Total: {worldData.worlds?.length || 0}
                                </div>
                            </div>
                            <div className="flex flex-col min-h-[400px]">
                                {worldData.worlds && worldData.worlds.length > 0 ? (
                                    worldData.worlds.map((world, idx) => (
                                        <WorldEntryRow 
                                            key={idx} 
                                            world={world} 
                                            isActive={world.name === worldData.activeWorld} 
                                            serverId={server.containerId}
                                        />
                                    ))
                                ) : (
                                    <div className="flex-1 flex flex-col items-center justify-center p-12 text-center">
                                        <i className="bi bi-globe-americas text-6xl text-neutral-800 mb-6 pulse"></i>
                                        <div className="text-lg font-bold text-neutral-600 uppercase tracking-[0.2em]">No worlds found</div>
                                        <p className="text-sm text-neutral-700 mt-2">Initialize your server to create your first world.</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Sidebar / Stats */}
                    <div className="lg:col-span-1 space-y-6">
                        <div className="bg-neutral-900 border border-neutral-800 rounded-3xl p-6 shadow-xl">
                            <h4 className="text-[10px] font-black text-primary-500 uppercase tracking-[0.3em] mb-4">Storage Info</h4>
                            <div className="space-y-4">
                                <div className="flex justify-between items-center text-sm">
                                    <span className="text-neutral-500">Active World</span>
                                    <span className="font-bold text-white font-mono">{worldData.activeWorld || 'N/A'}</span>
                                </div>
                                <div className="flex justify-between items-center text-sm">
                                    <span className="text-neutral-500">Location</span>
                                    <span className="text-neutral-300">Root Directory</span>
                                </div>
                                <div className="pt-4 border-t border-neutral-800">
                                    <p className="text-[10px] text-neutral-500 leading-relaxed italic">
                                        Changing the active world will update your server.properties automatically. A restart is required for changes to take effect.
                                    </p>
                                </div>
                            </div>
                        </div>

                        <div className="bg-primary-600/5 border border-primary-600/20 rounded-3xl p-6 shadow-inner">
                            <h4 className="text-[10px] font-black text-primary-400 uppercase tracking-[0.3em] mb-4 text-center">World Swap Alert</h4>
                            <p className="text-[11px] text-neutral-400 text-center leading-relaxed">
                                Always stop your server before cloning or downloading massive world folders to prevent session lock corruption.
                            </p>
                        </div>
                    </div>
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerMinecraftWorldCenterPage;

if (root) {
    root.render(
        <BrowserRouter>
            <ServerMinecraftWorldCenterPage pageData={data} />
        </BrowserRouter>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
