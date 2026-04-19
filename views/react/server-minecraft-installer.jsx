import React, { useState, useMemo, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-minecraft-installer';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

const DISTRIBUTIONS = [
    { id: 'archlight', name: 'Arclight', icon: 'bi-box-seam', description: 'Hybrid Spigot/Forge/Fabric server for modern versions.', color: 'bg-green-600/10 text-green-500' },
    { id: 'waterfall', name: 'Waterfall', icon: 'bi-water', description: 'High-performance BungeeCord fork for proxy networks.', color: 'bg-sky-600/10 text-sky-500' }
];

export function ServerMinecraftInstallerPage({ pageData = data }) {
    const server = pageData.server || {};
    const catalog = pageData.installerCatalog || {};
    const archlight = catalog.archlight || {};
    const waterfall = catalog.waterfall || {};
    const loaders = archlight.loaders || {};
    
    const [distribution, setDistribution] = useState('archlight');
    const [loader, setLoader] = useState('');
    const [version, setVersion] = useState('');
    const [build, setBuild] = useState('');
    const [targetFile, setTargetFile] = useState('server.jar');
    const [installModules, setInstallModules] = useState(false);
    const [installing, setInstalling] = useState(false);

    // Dynamic Options based on EJS logic
    const loaderOptions = useMemo(() => Object.keys(loaders), [loaders]);
    
    const versionOptions = useMemo(() => {
        if (distribution === 'waterfall') {
            return Object.keys(waterfall.versions || {});
        }
        if (loader && loaders[loader]) {
            return Object.keys(loaders[loader]);
        }
        return [];
    }, [distribution, loader, loaders, waterfall]);

    const buildOptions = useMemo(() => {
        if (distribution === 'waterfall') {
            return waterfall.versions?.[version]?.builds || [];
        }
        if (loader && version && loaders[loader]?.[version]) {
            return loaders[loader][version].map(b => b.name);
        }
        return [];
    }, [distribution, loader, version, loaders, waterfall]);

    const downloadPreview = useMemo(() => {
        if (!build) return 'Select a build to preview URL.';
        if (distribution === 'waterfall') {
            const base = (waterfall.baseUrl || '').endsWith('/') ? waterfall.baseUrl : `${waterfall.baseUrl}/`;
            return `${base}${encodeURIComponent(version)}/${encodeURIComponent(build)}`;
        } else {
            const base = (archlight.baseUrl || '').endsWith('/') ? archlight.baseUrl : `${archlight.baseUrl}/`;
            return `${base}${encodeURIComponent(build)}`;
        }
    }, [distribution, build, version, waterfall, archlight]);

    const waterfallModulesCount = useMemo(() => {
        if (distribution !== 'waterfall') return 0;
        return (waterfall.versions?.[version]?.modules || []).length;
    }, [distribution, version, waterfall]);

    useEffect(() => {
        setLoader(loaderOptions[0] || '');
        setVersion('');
        setBuild('');
    }, [distribution, loaderOptions]);

    useEffect(() => {
        setVersion(versionOptions[0] || '');
        setBuild('');
    }, [loader, versionOptions]);

    useEffect(() => {
        setBuild(buildOptions[0] || '');
    }, [version, buildOptions]);

    const handleInstall = () => {
        if (!build || installing) return;
        
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = `/server/${server.containerId}/minecraft/installer`;
        
        const fields = {
            distribution,
            loader,
            version,
            build,
            targetFile,
            installModules: installModules ? 'true' : 'false',
            _csrf: document.querySelector('meta[name="csrf-token"]')?.content || ''
        };

        Object.entries(fields).forEach(([k, v]) => {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = k;
            input.value = v;
            form.appendChild(input);
        });

        document.body.appendChild(form);
        setInstalling(true);
        form.submit();
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Version Installer">
            <PageContentBlock 
                title="Version Installer" 
                description={`Deploy specialized distributions directly to your ${server.name} instance.`}
                eyebrow="Provisioning"
            >
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-12">
                    <div className="lg:col-span-12 xl:col-span-8">
                        <div className="mb-12">
                            <h3 className="text-sm font-black text-white uppercase tracking-[0.2em] mb-8 flex items-center gap-3">
                                <span className="w-8 h-8 rounded-xl bg-neutral-900 border border-neutral-800 flex items-center justify-center text-[10px] shadow-2xl">1</span>
                                Choose Architecture
                            </h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {DISTRIBUTIONS.map((dist) => (
                                    <button
                                        key={dist.id}
                                        onClick={() => setDistribution(dist.id)}
                                        className={`group relative flex items-start gap-5 p-6 rounded-[2rem] border transition-all text-left ${distribution === dist.id ? 'bg-primary-600/10 border-primary-500/50 shadow-2xl shadow-primary-900/10 scale-[1.02]' : 'bg-neutral-900/40 border-neutral-800 hover:border-neutral-700'}`}
                                    >
                                        <div className={`shrink-0 w-16 h-16 rounded-2xl flex items-center justify-center text-2xl shadow-xl transition-transform group-hover:scale-110 duration-500 ${distribution === dist.id ? 'bg-primary-600 text-white shadow-primary-600/20' : dist.color}`}>
                                            <i className={`bi ${dist.icon}`}></i>
                                        </div>
                                        <div>
                                            <h4 className="font-black text-white uppercase tracking-[0.15em] text-xs mb-2 group-hover:text-primary-400 transition-colors">
                                                {dist.name}
                                            </h4>
                                            <p className="text-[10px] text-neutral-500 font-bold uppercase tracking-widest leading-relaxed opacity-80">
                                                {dist.description}
                                            </p>
                                        </div>
                                        {distribution === dist.id && (
                                            <div className="absolute top-6 right-6">
                                                <i className="bi bi-patch-check-fill text-primary-500 text-lg"></i>
                                            </div>
                                        )}
                                    </button>
                                ))}
                            </div>
                        </div>

                        <div className="bg-neutral-900 border border-neutral-800 rounded-[3rem] p-10 shadow-2xl shadow-black/40 relative overflow-hidden">
                            <div className="absolute top-0 right-0 p-8 opacity-5">
                                <i className="bi bi-gear-wide-connected text-9xl"></i>
                            </div>
                            
                            <h3 className="text-sm font-black text-white uppercase tracking-[0.2em] mb-10 flex items-center gap-3">
                                <span className="w-8 h-8 rounded-xl bg-neutral-800 flex items-center justify-center text-[10px]">2</span>
                                Build Configuration
                            </h3>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-10">
                                {distribution === 'archlight' && (
                                    <div className="group">
                                        <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 ml-1 group-hover:text-neutral-300 transition-colors">Loader Type</label>
                                        <select 
                                            value={loader} 
                                            onChange={(e) => setLoader(e.target.value)}
                                            className="w-full bg-neutral-950 border border-neutral-800 rounded-2xl px-5 py-4 text-xs font-black text-white focus:outline-none focus:border-primary-500/50 transition-all uppercase tracking-widest"
                                        >
                                            {loaderOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                                        </select>
                                    </div>
                                )}
                                <div>
                                    <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 ml-1">Minecraft Version</label>
                                    <select 
                                        value={version} 
                                        onChange={(e) => setVersion(e.target.value)}
                                        className="w-full bg-neutral-950 border border-neutral-800 rounded-2xl px-5 py-4 text-xs font-black text-white focus:outline-none focus:border-primary-500/50 transition-all uppercase tracking-widest"
                                    >
                                        <option value="" disabled>Select version...</option>
                                        {versionOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                                    </select>
                                </div>
                                <div className={distribution === 'waterfall' ? 'md:col-span-2' : ''}>
                                    <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 ml-1">Distribution Build</label>
                                    <select 
                                        value={build} 
                                        onChange={(e) => setBuild(e.target.value)}
                                        className="w-full bg-neutral-950 border border-neutral-800 rounded-2xl px-5 py-4 text-xs font-black text-white focus:outline-none focus:border-primary-500/50 transition-all uppercase tracking-widest"
                                    >
                                        <option value="" disabled>Select build...</option>
                                        {buildOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                                    </select>
                                </div>
                            </div>

                            <div className="bg-neutral-950 border border-neutral-800 rounded-[2rem] p-6 mb-10">
                                <div className="flex items-center justify-between gap-6 mb-6">
                                    <div className="flex items-center gap-4">
                                        <div className="w-10 h-10 rounded-xl bg-primary-600/10 flex items-center justify-center text-primary-500">
                                            <i className="bi bi-file-earmark-binary"></i>
                                        </div>
                                        <div>
                                            <h5 className="text-[10px] font-black text-white uppercase tracking-widest">Output Filename</h5>
                                            <p className="text-[9px] text-neutral-600 font-bold uppercase tracking-widest">Target executable jar</p>
                                        </div>
                                    </div>
                                    <input 
                                        type="text" 
                                        value={targetFile}
                                        onChange={(e) => setTargetFile(e.target.value)}
                                        className="bg-neutral-900 border border-neutral-800 rounded-xl px-4 py-2 text-xs font-mono text-white focus:outline-none focus:border-primary-500/50 text-right min-w-[160px]"
                                    />
                                </div>
                                
                                {distribution === 'waterfall' && waterfallModulesCount > 0 && (
                                    <div className="flex items-center justify-between p-4 bg-emerald-600/5 border border-emerald-900/20 rounded-2xl">
                                        <div className="flex items-center gap-4">
                                            <div className="w-8 h-8 rounded-lg bg-emerald-600/10 flex items-center justify-center text-emerald-500">
                                                <i className="bi bi-plugin"></i>
                                            </div>
                                            <span className="text-[10px] font-black text-emerald-500 uppercase tracking-widest">{waterfallModulesCount} Proxy Modules Available</span>
                                        </div>
                                        <label className="flex items-center gap-3 cursor-pointer group">
                                            <input 
                                                type="checkbox" 
                                                checked={installModules}
                                                onChange={(e) => setInstallModules(e.target.checked)}
                                                className="w-5 h-5 rounded-lg bg-neutral-950 border-neutral-800 checked:bg-emerald-600 focus:ring-emerald-500/50 focus:ring-2" 
                                            />
                                            <span className="text-[10px] font-black text-neutral-500 uppercase tracking-widest group-hover:text-white transition-colors">Install All</span>
                                        </label>
                                    </div>
                                )}
                            </div>

                            <div className="flex flex-col md:flex-row items-center gap-6">
                                <div className="flex-1">
                                    <div className="text-[9px] font-black text-neutral-600 uppercase tracking-[0.3em] mb-2 px-1">Source Preview</div>
                                    <code className="block w-full bg-neutral-950 p-4 rounded-xl text-[10px] text-amber-500 font-mono break-all border border-neutral-800">
                                        {downloadPreview}
                                    </code>
                                </div>
                                <button
                                    onClick={handleInstall}
                                    disabled={!build || installing}
                                    className={`shrink-0 px-10 py-5 rounded-2xl text-[11px] font-black uppercase tracking-[0.35em] transition-all shadow-2xl active:scale-95 flex items-center gap-4 ${!build || installing ? 'bg-neutral-800 text-neutral-600' : 'bg-primary-600 hover:bg-primary-500 text-white shadow-primary-900/30'}`}
                                >
                                    {installing ? (
                                        <div className="w-5 h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                                    ) : (
                                        <i className="bi bi-cloud-arrow-down-fill text-lg"></i>
                                    )}
                                    {installing ? 'Provisioning...' : 'Execute Deploy'}
                                </button>
                            </div>
                        </div>
                    </div>

                    <div className="lg:col-span-12 xl:col-span-4 flex flex-col gap-6">
                        <div className="bg-amber-600/5 border border-amber-600/20 rounded-[2.5rem] p-8">
                            <i className="bi bi-shield-exclamation text-amber-500 text-3xl mb-4 block"></i>
                            <h4 className="text-sm font-black text-amber-500 uppercase tracking-[0.2em] mb-3">Pre-Flight Warning</h4>
                            <p className="text-[11px] text-neutral-500 font-bold uppercase tracking-widest leading-relaxed mb-6">
                                Version installation is a destructive process for your startup JAR. Current world data and generic configs are safe, but it is highly recommended to take a snapshot first.
                            </p>
                            <a href={`/server/${server.containerId}/backups`} className="text-[10px] font-black text-amber-500 uppercase tracking-[0.2em] hover:text-amber-400 flex items-center gap-2">
                                <i className="bi bi-plus-circle"></i> Create Backup Now
                            </a>
                        </div>
                        
                        <div className="bg-neutral-900 border border-neutral-800 rounded-[2.5rem] p-8 flex-1">
                            <h4 className="text-[10px] font-black text-white uppercase tracking-[0.2em] mb-6 opacity-30">Distribution Info</h4>
                            <div className="space-y-6">
                                {distribution === 'archlight' ? (
                                    <>
                                        <div className="group">
                                            <div className="text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1 group-hover:text-primary-500 transition-colors">Arclight Hybrid</div>
                                            <p className="text-[10px] text-neutral-600 font-bold leading-relaxed uppercase tracking-widest">A modern Bukkit/Spigot/Paper server with support for Forge and Fabric mods. Perfect for modded networks needing plugin support.</p>
                                        </div>
                                        <div className="group">
                                            <div className="text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1 group-hover:text-primary-500 transition-colors">Version Support</div>
                                            <p className="text-[10px] text-neutral-600 font-bold leading-relaxed uppercase tracking-widest">Actively maintained for 1.16.5 up to the latest releases.</p>
                                        </div>
                                    </>
                                ) : (
                                    <>
                                        <div className="group">
                                            <div className="text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1 group-hover:text-sky-500 transition-colors">Waterfall Proxy</div>
                                            <p className="text-[10px] text-neutral-600 font-bold leading-relaxed uppercase tracking-widest">The high-performance fork of BungeeCord, designed for large networks that require additional stability and bug fixes.</p>
                                        </div>
                                        <div className="group">
                                            <div className="text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1 group-hover:text-sky-500 transition-colors">Module System</div>
                                            <p className="text-[10px] text-neutral-600 font-bold leading-relaxed uppercase tracking-widest">Supports native command modules like cmd_list and cmd_send, easily toggleable during installation.</p>
                                        </div>
                                    </>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
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