import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

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
    const [players, setPlayers] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [inspectedData, setInspectedData] = useState(null);
    const [isInspecting, setIsInspecting] = useState(false);
    const [isResetting, setIsResetting] = useState(false);
    const [resetMessage, setResetMessage] = useState('');

    useEffect(() => {
        let active = true;
        async function fetchPlayers() {
            try {
                const response = await fetch(`/server/${server.containerId}/minecraft/admin/players`);
                const payload = await response.json();
                if (!response.ok || !payload.success) throw new Error(payload.error || 'Failed to fetch players.');
                if (active) {
                    setPlayers(payload.players || []);
                    setError(null);
                }
            } catch (err) {
                if (active) setError(err.message || 'Player sync failed');
            } finally {
                if (active) setIsLoading(false);
            }
        }
        
        fetchPlayers();
        const interval = setInterval(fetchPlayers, 30000); // Polling every 30 seconds
        
        return () => {
            active = false;
            clearInterval(interval);
        };
    }, [server.containerId]);

    useEffect(() => {
        if (!selectedPlayer) {
            setInspectedData(null);
            return;
        }

        let active = true;
        async function fetchDetails() {
            setIsInspecting(true);
            try {
                const response = await fetch(`/server/${server.containerId}/minecraft/admin/inspect?username=${encodeURIComponent(selectedPlayer.name)}&refresh=true`);
                const payload = await response.json();
                if (active && payload.success) {
                    setInspectedData(payload);
                }
            } catch (err) {
                console.error("Failed to fetch player details", err);
            } finally {
                if (active) setIsInspecting(false);
            }
        }

        fetchDetails();
        return () => { active = false; };
    }, [selectedPlayer, server.containerId]);

    const profile = inspectedData?.profile || {};
    const vitals = profile.vitals || {};
    const location = profile.location || {};

    const filteredPlayers = players.filter(p => String(p.name || '').toLowerCase().includes(searchQuery.toLowerCase()));

    const handleResetThrottle = async () => {
        setIsResetting(true);
        setResetMessage('');
        try {
            const response = await fetch(`/server/${server.containerId}/minecraft/admin/reset-throttle`, { method: 'POST' });
            const payload = await response.json();
            if (payload.success) {
                setResetMessage('Success: Command budget reset.');
                setTimeout(() => setResetMessage(''), 5000);
            } else {
                setResetMessage(`Error: ${payload.error || 'Failed to reset budget'}`);
            }
        } catch (err) {
            setResetMessage('Error: Failed to reach backend');
        } finally {
            setIsResetting(false);
        }
    };

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
                                    <div className={`w-2 h-2 rounded-full ${p.online ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-neutral-600'}`}></div>
                                </button>
                            ))}
                        </div>

                        {/* Troubleshooting Section */}
                        <div className="p-6 border-t border-neutral-800 bg-neutral-900/40">
                            <h4 className="text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 flex items-center gap-2">
                                <i className="bi bi-cpu"></i> Troubleshooting
                            </h4>
                            <button 
                                onClick={handleResetThrottle}
                                disabled={isResetting}
                                className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-neutral-800 hover:bg-neutral-700 disabled:opacity-50 text-neutral-300 rounded-xl text-xs font-bold transition-all border border-neutral-700/50"
                            >
                                {isResetting ? <div className="w-3 h-3 border-2 border-neutral-500 border-t-white rounded-full animate-spin"></div> : <i className="bi bi-clock-history"></i>}
                                Reset Command Budget
                            </button>
                            {resetMessage && (
                                <div className={`mt-3 text-[10px] font-bold text-center ${resetMessage.startsWith('Error') ? 'text-rose-400' : 'text-green-400'}`}>
                                    {resetMessage}
                                </div>
                            )}
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
                                    <div className="flex flex-col items-end gap-2">
                                        <div className={`px-4 py-1.5 rounded-full text-[10px] font-black uppercase tracking-widest border ${selectedPlayer.online ? 'bg-green-500/10 text-green-400 border-green-500/20' : 'bg-neutral-800 text-neutral-400 border-neutral-700'}`}>
                                            {selectedPlayer.online ? 'Online Now' : 'Offline'}
                                        </div>
                                        <div className="text-[9px] font-black uppercase tracking-tighter text-neutral-500 bg-neutral-800/50 px-2 py-0.5 rounded border border-neutral-700/30">
                                            Source: {selectedPlayer.source === 'live_status' ? 'Live Query' : 'Registry Files'}
                                        </div>
                                    </div>
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div className="bg-neutral-800/40 rounded-2xl p-6 border border-neutral-800">
                                        <h4 className="text-xs font-black text-neutral-500 uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
                                            <i className="bi bi-heart-pulse"></i> Vitals
                                        </h4>
                                        <div className={`space-y-4 transition-opacity ${isInspecting ? 'opacity-50' : 'opacity-100'}`}>
                                            <div>
                                                <div className="flex justify-between text-xs font-bold mb-1">
                                                    <span className="text-rose-400">Health</span>
                                                    <span className="text-white">{vitals.health !== undefined ? `${parseFloat(vitals.health).toFixed(1)}/20` : '--/--'}</span>
                                                </div>
                                                <div className="h-2 rounded-full bg-neutral-900 border border-neutral-800 overflow-hidden">
                                                    <div className="h-full bg-rose-500 transition-all duration-500" style={{ width: `${Math.min(100, (parseFloat(vitals.health) || 0) * 5)}%` }}></div>
                                                </div>
                                            </div>
                                            <div>
                                                <div className="flex justify-between text-xs font-bold mb-1">
                                                    <span className="text-amber-400">Food</span>
                                                    <span className="text-white">{vitals.food !== undefined ? `${vitals.food}/20` : '--/--'}</span>
                                                </div>
                                                <div className="h-2 rounded-full bg-neutral-900 border border-neutral-800 overflow-hidden">
                                                    <div className="h-full bg-amber-500 transition-all duration-500" style={{ width: `${Math.min(100, (parseFloat(vitals.food) || 0) * 5)}%` }}></div>
                                                </div>
                                            </div>
                                            <div>
                                                <div className="flex justify-between text-xs font-bold mb-1">
                                                    <span className="text-green-400">Experience Level</span>
                                                    <span className="text-white">{vitals.xpLevel !== undefined ? vitals.xpLevel : '--'}</span>
                                                </div>
                                                <div className="h-2 rounded-full bg-neutral-900 border border-neutral-800 overflow-hidden">
                                                    <div className="h-full bg-green-500 transition-all duration-500" style={{ width: `${Math.min(100, (parseFloat(vitals.xpLevel) || 0) * 2)}%` }}></div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="bg-neutral-800/40 rounded-2xl p-6 border border-neutral-800">
                                        <h4 className="text-xs font-black text-neutral-500 uppercase tracking-[0.2em] mb-4 flex items-center gap-2">
                                            <i className="bi bi-geo-alt"></i> Location
                                        </h4>
                                        <div className={`grid grid-cols-2 gap-4 transition-opacity ${isInspecting ? 'opacity-50' : 'opacity-100'}`}>
                                            <div>
                                                <div className="text-[10px] uppercase font-black text-neutral-500 mb-1">World</div>
                                                <div className="text-sm font-bold text-white bg-neutral-900 px-3 py-2 rounded-lg border border-neutral-800 truncate">{location.dimension || 'unknown'}</div>
                                            </div>
                                            <div>
                                                <div className="text-[10px] uppercase font-black text-neutral-500 mb-1">Coordinates</div>
                                                <div className="text-sm font-bold text-white bg-neutral-900 px-3 py-2 rounded-lg border border-neutral-800 font-mono truncate">{location.coordinates || 'N/A'}</div>
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
        <ThemeProvider pageData={data}>
            <BrowserRouter>
            <ServerMinecraftAdminPage pageData={data} />
        </BrowserRouter>
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}