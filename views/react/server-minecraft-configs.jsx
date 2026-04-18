import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-minecraft-configs';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ServerMinecraftConfigsPage({ pageData = data }) {
    const server = pageData.server || {};
    const {
        minecraftStatusAddress = '',
        minecraftBedrockMode = false,
        minecraftProxyMode = null,
        connectorOnline = false,
        minecraftMotd = '',
        minecraftResourcePack = {},
        minecraftMotdPresets = [],
        minecraftPropertiesError = ''
    } = pageData;

    const [proxyInstalling, setProxyInstalling] = useState(false);
    
    const handleSaveMotd = (e) => {
        e.preventDefault();
        const form = e.target;
        form.submit();
    };

    const handleSaveProxy = (e) => {
        e.preventDefault();
        setProxyInstalling(true);
        e.target.submit();
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Minecraft Control">
            <PageContentBlock 
                title="Minecraft Control" 
                description="Core server properties, MOTD presets, proxy setup, and resource packs."
                eyebrow="Configuration"
            >
                {minecraftPropertiesError && (
                    <div className="mb-8 bg-rose-600/10 border border-rose-600/20 text-rose-500 p-6 rounded-3xl flex items-center gap-4">
                        <i className="bi bi-exclamation-octagon text-2xl"></i>
                        <div>
                            <h4 className="font-bold text-sm uppercase tracking-widest">Configuration Read Error</h4>
                            <p className="text-xs text-rose-400 mt-1">{minecraftPropertiesError}</p>
                        </div>
                    </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
                    {/* MOTD Configuration */}
                    <div className="bg-neutral-800/40 border border-neutral-800 rounded-[2rem] p-8 shadow-2xl">
                        <div className="flex items-center gap-4 mb-8">
                            <div className="w-12 h-12 rounded-2xl bg-primary-600/10 flex items-center justify-center text-primary-500 text-xl shadow-inner">
                                <i className="bi bi-fonts"></i>
                            </div>
                            <div>
                                <h3 className="text-sm font-black text-white uppercase tracking-[0.2em]">Server MOTD</h3>
                                <p className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest mt-1">Message of the day</p>
                            </div>
                        </div>

                        <form method="POST" action={`/server/${server.containerId}/minecraft/configs/motd`} onSubmit={handleSaveMotd}>
                            <input type="hidden" name="_csrf" value={document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''} />
                            
                            <textarea 
                                name="motd" 
                                defaultValue={minecraftMotd}
                                rows="3"
                                className="w-full bg-neutral-900 border border-neutral-700/50 rounded-2xl px-5 py-4 text-sm text-white focus:border-primary-500 transition-colors outline-none font-mono resize-none mb-6 shadow-inner"
                                placeholder="A Minecraft Server..."
                            ></textarea>

                            <div className="flex justify-between items-center">
                                <button type="button" className="text-[10px] font-black text-primary-500 hover:text-primary-400 uppercase tracking-[0.2em] transition-colors">
                                    <i className="bi bi-palette flex items-center gap-2">Presets</i>
                                </button>
                                <button type="submit" disabled={!connectorOnline} className={`px-8 py-3 rounded-xl text-xs font-black uppercase tracking-[0.2em] transition-all shadow-xl active:scale-95 flex items-center gap-3 ${connectorOnline ? 'bg-primary-600 hover:bg-primary-500 text-white shadow-primary-900/20' : 'bg-neutral-800 text-neutral-600 cursor-not-allowed'}`}>
                                    <i className="bi bi-save"></i> Save Changes
                                </button>
                            </div>
                        </form>
                    </div>

                    {/* Proxy Network Mode */}
                    <div className="bg-neutral-800/40 border border-neutral-800 rounded-[2rem] p-8 shadow-2xl relative overflow-hidden">
                        <div className="absolute top-0 right-0 p-8 opacity-5">
                            <i className="bi bi-diagram-3 text-9xl"></i>
                        </div>
                        <div className="relative">
                            <div className="flex items-center gap-4 mb-8">
                                <div className="w-12 h-12 rounded-2xl bg-purple-600/10 flex items-center justify-center text-purple-500 text-xl shadow-inner">
                                    <i className="bi bi-diagram-3"></i>
                                </div>
                                <div>
                                    <h3 className="text-sm font-black text-white uppercase tracking-[0.2em]">Proxy Setup</h3>
                                    <p className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest mt-1">BungeeCord / Velocity</p>
                                </div>
                            </div>

                            <p className="text-sm text-neutral-400 font-medium mb-6 leading-relaxed">
                                Currently operating in <strong className={minecraftProxyMode && minecraftProxyMode !== 'disabled' ? 'text-purple-400' : 'text-primary-400'}>{minecraftProxyMode || 'disabled'}</strong> mode.
                            </p>

                            <form method="POST" action={`/server/${server.containerId}/minecraft/configs/proxy-mode`} onSubmit={handleSaveProxy}>
                                <input type="hidden" name="_csrf" value={document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''} />
                                
                                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
                                    {['disabled', 'bungeecord', 'velocity'].map(mode => (
                                        <label key={mode} className={`relative flex items-center justify-center px-4 py-3 rounded-xl border cursor-pointer transition-all ${minecraftProxyMode === mode ? 'bg-purple-600/10 border-purple-500 text-purple-400' : 'bg-neutral-900 border-neutral-800 text-neutral-500 hover:border-neutral-700'}`}>
                                            <input type="radio" name="proxyMode" value={mode} defaultChecked={minecraftProxyMode === mode} className="sr-only" />
                                            <span className="text-[10px] font-black uppercase tracking-widest">{mode}</span>
                                        </label>
                                    ))}
                                </div>

                                <button type="submit" disabled={proxyInstalling || !connectorOnline} className={`w-full py-4 rounded-xl text-xs font-black uppercase tracking-[0.2em] transition-all flex justify-center items-center gap-3 ${proxyInstalling || !connectorOnline ? 'bg-neutral-800 text-neutral-600' : 'bg-neutral-100/10 hover:bg-neutral-100/20 text-white'}`}>
                                    {proxyInstalling ? (
                                        <><div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin"></div> Reconfiguring...</>
                                    ) : (
                                        <><i className="bi bi-arrow-repeat"></i> Apply Strategy</>
                                    )}
                                </button>
                            </form>
                        </div>
                    </div>
                </div>

                {/* Resource Pack */}
                <div className="bg-neutral-800/40 border border-neutral-800 rounded-[2rem] p-8 shadow-2xl mb-8">
                    <div className="flex items-center gap-4 mb-8">
                        <div className="w-12 h-12 rounded-2xl bg-amber-600/10 flex items-center justify-center text-amber-500 text-xl shadow-inner">
                            <i className="bi bi-box-seam"></i>
                        </div>
                        <div>
                            <h3 className="text-sm font-black text-white uppercase tracking-[0.2em]">Global Resource Pack</h3>
                            <p className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest mt-1">Automatic Client Downloads</p>
                        </div>
                    </div>

                    <form method="POST" action={`/server/${server.containerId}/minecraft/configs/resource-pack`} className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <input type="hidden" name="_csrf" value={document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''} />
                        
                        <div>
                            <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] mb-3">Direct Download URL</label>
                            <input 
                                type="url" 
                                name="url" 
                                defaultValue={minecraftResourcePack.url || ''} 
                                placeholder="https://example.com/pack.zip"
                                className="w-full bg-neutral-900 border border-neutral-700/50 rounded-xl px-4 py-3 text-sm text-white focus:border-amber-500 transition-colors outline-none font-mono shadow-inner"
                            />
                        </div>
                        
                        <div>
                            <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] mb-3">SHA-1 Hash</label>
                            <input 
                                type="text" 
                                name="sha1" 
                                defaultValue={minecraftResourcePack.sha1 || ''} 
                                placeholder="Must be valid SHA-1"
                                className="w-full bg-neutral-900 border border-neutral-700/50 rounded-xl px-4 py-3 text-sm text-white focus:border-amber-500 transition-colors outline-none font-mono shadow-inner mb-4"
                            />
                            
                            <label className="flex items-center gap-3 cursor-pointer group">
                                <input type="checkbox" name="required" defaultChecked={minecraftResourcePack.required} className="w-5 h-5 rounded bg-neutral-900 border border-neutral-700 text-amber-500 focus:ring-amber-500 focus:ring-offset-neutral-900 transition-colors cursor-pointer" />
                                <span className="text-xs font-bold text-neutral-400 group-hover:text-white uppercase tracking-wider transition-colors">Enforce Pack on Join</span>
                            </label>
                        </div>

                        <div className="md:col-span-2 flex justify-end">
                            <button type="submit" disabled={!connectorOnline} className={`px-10 py-4 rounded-xl text-xs font-black uppercase tracking-[0.2em] transition-all shadow-xl flex items-center gap-3 ${connectorOnline ? 'bg-amber-600 hover:bg-amber-500 text-white shadow-amber-900/20' : 'bg-neutral-800 text-neutral-600 cursor-not-allowed'}`}>
                                <i className="bi bi-cloud-arrow-up"></i> Update Config
                            </button>
                        </div>
                    </form>
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerMinecraftConfigsPage;

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <BrowserRouter>
            <ServerMinecraftConfigsPage pageData={data} />
        </BrowserRouter>
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}