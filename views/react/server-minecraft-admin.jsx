import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-minecraft-admin';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ServerMinecraftAdminPage({ pageData = data }) {
    const server = pageData.server || {};
    const { 
        minecraftAdminPermissions = {},
        minecraftAdminRecentEvents = [] 
    } = pageData;

    const [searchQuery, setSearchQuery] = useState('');
    const [selectedPlayer, setSelectedPlayer] = useState(null);

    // Mock player for visual representation until hooked to socket
    const players = [
        { name: 'Notch', uuid: '069a79f4-44e9-4726-a5be-fca90e38aaf5', isOnline: true },
        { name: 'Jeb_', uuid: '853c80ef-3c37-49fd-aa49-938b674adae6', isOnline: false }
    ];

    const filteredPlayers = players.filter(p => p.name.toLowerCase().includes(searchQuery.toLowerCase()));

    return (
        <ReactAppShell pageData={pageData} subtitle="Admin & Control">
            <PageContentBlock 
                title="Admin & Control" 
                description="Live player directory, administrative actions, and instance metrics."
                eyebrow="Moderation"
            >
                <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
                    {/* Left Sidebar - Player Directory */}
                    <div className="xl:col-span-4 flex flex-col h-[800px] bg-neutral-900/60 backdrop-blur-xl border border-neutral-800 rounded-[2rem] shadow-2xl overflow-hidden">
                        <div className="p-6 border-b border-neutral-800">
                            <h3 className="text-sm font-black text-white uppercase tracking-[0.2em] mb-4">Player Directory</h3>
                            <div className="relative">
                                <i className="bi bi-search absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500"></i>
                                <input 
                                    type="text" 
                                    placeholder="Search by username..."
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                    className="w-full bg-neutral-800 border border-neutral-700 rounded-xl py-3 pl-10 pr-4 text-sm text-neutral-200 focus:border-primary-500 outline-none transition-colors"
                                />
                            </div>
                        </div>
                        <div className="flex-1 overflow-y-auto p-4 space-y-2">
                            {filteredPlayers.map(p => (
                                <button 
                                    key={p.name}
                                    onClick={() => setSelectedPlayer(p)}
                                    className={`w-full flex items-center gap-4 p-3 rounded-xl transition-all border text-left ${selectedPlayer?.name === p.name ? 'bg-primary-600/10 border-primary-500/50' : 'bg-transparent border-transparent hover:bg-neutral-800 hover:border-neutral-700'}`}
                                >
                                    <img src={`https://mc-heads.net/avatar/${p.uuid}/100.png`} alt={p.name} className="w-10 h-10 rounded-lg shadow-sm" />
                                    <div className="flex-1 min-w-0">
                                        <div className="font-bold text-sm text-white truncate">{p.name}</div>
                                        <div className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest truncate">{p.uuid}</div>
                                    </div>
                                    <div className={`w-2 h-2 rounded-full ${p.isOnline ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-neutral-600'}`}></div>
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Right Panel - Player Inspector */}
                    <div className="xl:col-span-8 flex flex-col h-[800px]">
                        {!selectedPlayer ? (
                            <div className="flex-1 flex flex-col items-center justify-center border-2 border-dashed border-neutral-800 rounded-[2rem] text-center p-8">
                                <i className="bi bi-person-badge text-6xl text-neutral-800 mb-6"></i>
                                <h3 className="text-lg font-black text-white uppercase tracking-widest mb-2">Select a Player</h3>
                                <p className="text-sm text-neutral-500 font-bold max-w-sm leading-relaxed">Choose a player from the directory to inspect their inventory, execute commands, or manage moderation tools.</p>
                            </div>
                        ) : (
                            <div className="flex-1 bg-neutral-900/60 backdrop-blur-xl border border-neutral-800 rounded-[2rem] shadow-2xl p-8 overflow-y-auto">
                                <div className="flex items-start gap-6 border-b border-neutral-800 pb-8 mb-8">
                                    <img src={`https://mc-heads.net/avatar/${selectedPlayer.uuid}/200.png`} alt={selectedPlayer.name} className="w-24 h-24 rounded-2xl shadow-xl ring-1 ring-white/10" />
                                    <div className="flex-1">
                                        <h2 className="text-2xl font-black text-white tracking-tight mb-1">{selectedPlayer.name}</h2>
                                        <p className="text-xs text-neutral-400 font-mono mb-4 bg-neutral-800 inline-block px-3 py-1 rounded-md">{selectedPlayer.uuid}</p>
                                        
                                        <div className="flex flex-wrap gap-2">
                                            {minecraftAdminPermissions.kick && (
                                                <button className="px-5 py-2 bg-neutral-800 hover:bg-rose-600/20 hover:text-rose-400 text-neutral-300 rounded-lg text-xs font-black uppercase tracking-widest transition-all">Kick</button>
                                            )}
                                            {minecraftAdminPermissions.ban && (
                                                <button className="px-5 py-2 bg-rose-600/10 text-rose-500 hover:bg-rose-600 hover:text-white rounded-lg text-xs font-black uppercase tracking-widest transition-all border border-rose-600/20">Ban</button>
                                            )}
                                            {minecraftAdminPermissions.op && (
                                                <button className="px-5 py-2 bg-primary-600/10 text-primary-500 hover:bg-primary-600 hover:text-white rounded-lg text-xs font-black uppercase tracking-widest transition-all border border-primary-600/20">Make Operator</button>
                                            )}
                                        </div>
                                    </div>
                                    <div className={`px-4 py-1.5 rounded-full text-[10px] font-black uppercase tracking-widest border ${selectedPlayer.isOnline ? 'bg-green-500/10 text-green-400 border-green-500/20' : 'bg-neutral-800 text-neutral-400 border-neutral-700'}`}>
                                        {selectedPlayer.isOnline ? 'Online Now' : 'Offline'}
                                    </div>
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div className="bg-neutral-800/40 rounded-2xl p-6 border border-neutral-800">
                                        <h4 className="text-xs font-black text-neutral-500 uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
                                            <i className="bi bi-heart-pulse"></i> Vitals
                                        </h4>
                                        <div className="space-y-4">
                                            <div>
                                                <div className="flex justify-between text-xs font-bold mb-1">
                                                    <span className="text-rose-400">Health</span>
                                                    <span className="text-white">20/20</span>
                                                </div>
                                                <div className="h-2 rounded-full bg-neutral-900 border border-neutral-800 overflow-hidden">
                                                    <div className="h-full bg-rose-500 w-full"></div>
                                                </div>
                                            </div>
                                            <div>
                                                <div className="flex justify-between text-xs font-bold mb-1">
                                                    <span className="text-amber-400">Food</span>
                                                    <span className="text-white">20/20</span>
                                                </div>
                                                <div className="h-2 rounded-full bg-neutral-900 border border-neutral-800 overflow-hidden">
                                                    <div className="h-full bg-amber-500 w-full"></div>
                                                </div>
                                            </div>
                                            <div>
                                                <div className="flex justify-between text-xs font-bold mb-1">
                                                    <span className="text-green-400">Experience Level</span>
                                                    <span className="text-white">12</span>
                                                </div>
                                                <div className="h-2 rounded-full bg-neutral-900 border border-neutral-800 overflow-hidden">
                                                    <div className="h-full bg-green-500 w-[45%]"></div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="bg-neutral-800/40 rounded-2xl p-6 border border-neutral-800">
                                        <h4 className="text-xs font-black text-neutral-500 uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
                                            <i className="bi bi-geo-alt"></i> Location
                                        </h4>
                                        <div className="grid grid-cols-2 gap-4">
                                            <div>
                                                <div className="text-[10px] uppercase font-black text-neutral-500 mb-1">World</div>
                                                <div className="text-sm font-bold text-white bg-neutral-900 px-3 py-2 rounded-lg border border-neutral-800">world</div>
                                            </div>
                                            <div>
                                                <div className="text-[10px] uppercase font-black text-neutral-500 mb-1">Coordinates</div>
                                                <div className="text-sm font-bold text-white bg-neutral-900 px-3 py-2 rounded-lg border border-neutral-800 font-mono">142, 64, -89</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerMinecraftAdminPage;

if (root) {
    root.render(
        <BrowserRouter>
            <ServerMinecraftAdminPage pageData={data} />
        </BrowserRouter>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
