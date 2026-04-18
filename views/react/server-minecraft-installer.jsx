import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-minecraft-installer';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

const PLATFORMS = [
    { id: 'vanilla', name: 'Vanilla', icon: 'bi-box-seam', description: 'The official Minecraft server jar from Mojang.', color: 'bg-green-600/10 text-green-500' },
    { id: 'fabric', name: 'Fabric', icon: 'bi-cpu', description: 'Lightweight, modular modding toolset for modern versions.', color: 'bg-orange-600/10 text-orange-500' },
    { id: 'forge', name: 'Forge', icon: 'bi-hammer', description: 'The original modding API for extensive content mods.', color: 'bg-blue-600/10 text-blue-500' },
    { id: 'quilt', name: 'Quilt', icon: 'bi-patch-check', description: 'Community-driven mod loader built for modularity.', color: 'bg-purple-600/10 text-purple-500' },
    { id: 'waterfall', name: 'Waterfall', icon: 'bi-water', description: 'High-performance BungeeCord fork for proxy networks.', color: 'bg-sky-600/10 text-sky-500' },
    { id: 'bungeecord', name: 'BungeeCord', icon: 'bi-intersect', description: 'The standard proxy for connecting multiple servers.', color: 'bg-yellow-600/10 text-yellow-500' }
];

export function ServerMinecraftInstallerPage({ pageData = data }) {
    const server = pageData.server || {};
    const catalog = pageData.installerCatalog || {};

    const [selectedPlatform, setSelectedPlatform] = React.useState(null);
    const [selectedVersion, setSelectedVersion] = React.useState('');
    const [selectedBuild, setSelectedBuild] = React.useState('');
    const [installing, setInstalling] = React.useState(false);
    const [error, setError] = React.useState(pageData.error || null);
    const [success, setSuccess] = React.useState(pageData.success || null);

    const availableVersions = React.useMemo(() => {
        if (!selectedPlatform) return [];
        const platformKey = selectedPlatform.toLowerCase();
        
        // Handle waterfall specifically based on catalog structure
        if (platformKey === 'waterfall' && catalog.waterfall) {
            return Object.keys(catalog.waterfall).sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
        }
        
        // Handle archlight or others if present...
        // For now we'll assume a generic structure or use common defaults
        return [];
    }, [selectedPlatform, catalog]);

    const handlePlatformSelect = (platform) => {
        setSelectedPlatform(platform.id);
        setSelectedVersion('');
        setSelectedBuild('');
        setError(null);
    };

    const handleInstall = () => {
        if (!selectedPlatform || !selectedVersion) return;
        
        // We'll submit via standard form POST to reuse existing backend logic comfortably
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = `/server/${server.containerId}/minecraft/installer`;
        
        const platInput = document.createElement('input');
        platInput.name = 'platform';
        platInput.value = selectedPlatform;
        form.appendChild(platInput);
        
        const verInput = document.createElement('input');
        verInput.name = 'version';
        verInput.value = selectedVersion;
        form.appendChild(verInput);
        
        if (selectedBuild) {
            const buildInput = document.createElement('input');
            buildInput.name = 'build';
            buildInput.value = selectedBuild;
            form.appendChild(buildInput);
        }

        // Add CSRF
        const csrfInput = document.createElement('input');
        csrfInput.type = 'hidden';
        csrfInput.name = '_csrf';
        csrfInput.value = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
        form.appendChild(csrfInput);

        document.body.appendChild(form);
        setInstalling(true);
        form.submit();
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Version Installer">
            <PageContentBlock 
                title="Version Installer" 
                description="Easily switch between different Minecraft platforms and versions."
                eyebrow="Provisioning"
            >
                {error && (
                    <div className="mb-8 bg-rose-600/10 border border-rose-600/20 text-rose-500 p-6 rounded-3xl flex items-center gap-4 animate-in slide-in-from-top-4">
                        <i className="bi bi-exclamation-octagon text-2xl"></i>
                        <span className="font-bold uppercase tracking-widest text-sm">{error}</span>
                    </div>
                )}

                {success && (
                    <div className="mb-8 bg-emerald-600/10 border border-emerald-600/20 text-emerald-500 p-6 rounded-3xl flex items-center gap-4 animate-in slide-in-from-top-4">
                        <i className="bi bi-check-circle text-2xl"></i>
                        <span className="font-bold uppercase tracking-widest text-sm">{success}</span>
                    </div>
                )}

                <div className="mb-10">
                    <h3 className="text-sm font-black text-white uppercase tracking-[0.2em] mb-6 flex items-center gap-3">
                        <span className="w-6 h-6 rounded-lg bg-neutral-800 flex items-center justify-center text-[10px]">1</span>
                        Select Platform
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {PLATFORMS.map((platform) => (
                            <button
                                key={platform.id}
                                onClick={() => handlePlatformSelect(platform)}
                                className={`group flex items-start gap-4 p-5 rounded-2xl border transition-all text-left ${selectedPlatform === platform.id ? 'bg-primary-600/10 border-primary-500 shadow-xl shadow-primary-900/10' : 'bg-neutral-800/40 border-neutral-800 hover:border-neutral-700'}`}
                            >
                                <div className={`shrink-0 w-12 h-12 rounded-xl flex items-center justify-center text-xl shadow-lg ${selectedPlatform === platform.id ? 'bg-primary-600 text-white' : platform.color}`}>
                                    <i className={`bi ${platform.icon}`}></i>
                                </div>
                                <div>
                                    <h4 className="font-black text-white uppercase tracking-widest text-xs mb-1 group-hover:text-primary-400 transition-colors">
                                        {platform.name}
                                    </h4>
                                    <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest leading-relaxed">
                                        {platform.description}
                                    </p>
                                </div>
                            </button>
                        ))}
                    </div>
                </div>

                {selectedPlatform && (
                    <div className="animate-in fade-in slide-in-from-top-4 duration-500">
                        <h3 className="text-sm font-black text-white uppercase tracking-[0.2em] mb-6 flex items-center gap-3">
                            <span className="w-6 h-6 rounded-lg bg-neutral-800 flex items-center justify-center text-[10px]">2</span>
                            Configure Installation
                        </h3>
                        <div className="bg-neutral-800/40 border border-neutral-800 rounded-3xl p-8 max-w-2xl">
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-8">
                                <div>
                                    <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] mb-3">
                                        Target Version
                                    </label>
                                    <input 
                                        type="text"
                                        placeholder="e.g. 1.20.1"
                                        value={selectedVersion}
                                        onChange={(e) => setSelectedVersion(e.target.value)}
                                        className="w-full bg-neutral-900 border border-neutral-700 rounded-xl px-4 py-3 text-sm text-white focus:border-primary-500 transition-colors outline-none font-mono"
                                    />
                                    {selectedPlatform === 'waterfall' && availableVersions.length > 0 && (
                                        <div className="mt-2 flex flex-wrap gap-2">
                                            {availableVersions.slice(0, 5).map(v => (
                                                <button key={v} onClick={() => setSelectedVersion(v)} className="text-[9px] font-bold text-neutral-600 hover:text-white transition-colors">{v}</button>
                                            ))}
                                        </div>
                                    )}
                                </div>
                                {['forge', 'fabric', 'quilt', 'waterfall'].includes(selectedPlatform) && (
                                    <div>
                                        <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-[0.2em] mb-3">
                                            Build / Loader
                                        </label>
                                        <input 
                                            type="text"
                                            placeholder="Leave blank for latest"
                                            value={selectedBuild}
                                            onChange={(e) => setSelectedBuild(e.target.value)}
                                            className="w-full bg-neutral-900 border border-neutral-700 rounded-xl px-4 py-3 text-sm text-white focus:border-primary-500 transition-colors outline-none font-mono"
                                        />
                                    </div>
                                )}
                            </div>

                            <div className="bg-rose-600/5 border border-rose-600/20 p-5 rounded-2xl mb-8">
                                <div className="flex items-start gap-4">
                                    <i className="bi bi-shield-exclamation text-rose-500 text-xl"></i>
                                    <div>
                                        <h5 className="text-[10px] font-black text-rose-500 uppercase tracking-[0.2em] mb-1">Destructive Action</h5>
                                        <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest leading-relaxed">
                                            This will stop your server and overwrite the primary executable. Current world files will be preserved.
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <button
                                onClick={handleInstall}
                                disabled={!selectedVersion || installing}
                                className={`w-full py-4 rounded-xl text-xs font-black uppercase tracking-[0.3em] transition-all shadow-xl active:scale-95 flex items-center justify-center gap-3 ${!selectedVersion || installing ? 'bg-neutral-800 text-neutral-600 cursor-not-allowed' : 'bg-primary-600 hover:bg-primary-500 text-white shadow-primary-900/20'}`}
                            >
                                {installing ? (
                                    <>
                                        <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                                        Processing...
                                    </>
                                ) : (
                                    <>
                                        <i className="bi bi-download"></i>
                                        Install {PLATFORMS.find(p => p.id === selectedPlatform)?.name} {selectedVersion}
                                    </>
                                )}
                            </button>
                        </div>
                    </div>
                )}
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerMinecraftInstallerPage;

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <BrowserRouter>
            <ServerMinecraftInstallerPage pageData={data} />
        </BrowserRouter>
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}