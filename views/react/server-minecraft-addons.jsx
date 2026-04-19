import React, { useState, useEffect, useMemo } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-minecraft-addons';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function AddonCard({ project, onInstall }) {
    return (
        <div className="bg-neutral-900 border border-neutral-800 rounded-3xl overflow-hidden group hover:border-primary-500/50 transition-all duration-300 flex flex-col hover:shadow-2xl hover:shadow-primary-900/10 hover:translate-y-[-2px]">
            <div className="relative aspect-video overflow-hidden bg-neutral-950">
                <img 
                    src={project.gallery && project.gallery[0] ? project.gallery[0].url : project.icon_url || 'https://cdn.modrinth.com/assets/images/default_project_icon.svg'} 
                    alt={project.title} 
                    className="w-full h-full object-cover opacity-60 group-hover:opacity-100 transition-opacity duration-500"
                />
                <div className="absolute top-4 right-4 bg-neutral-900/80 backdrop-blur-md px-3 py-1 rounded-full text-[10px] font-black text-primary-400 uppercase tracking-widest border border-primary-900/30">
                    {project.project_type}
                </div>
            </div>
            <div className="p-6 flex-1 flex flex-col">
                <h3 className="text-lg font-black text-white mb-2 line-clamp-1">{project.title}</h3>
                <p className="text-xs text-neutral-500 leading-relaxed line-clamp-2 mb-6 flex-1 font-medium">{project.description}</p>
                <div className="flex items-center justify-between mt-auto pt-4 border-t border-neutral-800">
                    <div className="flex items-center gap-2">
                        <i className="bi bi-download text-neutral-600"></i>
                        <span className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest">{Math.round(project.downloads / 1000)}K DLs</span>
                    </div>
                    <button 
                        onClick={() => onInstall(project)}
                        className="px-4 py-2 bg-neutral-800 hover:bg-neutral-700 text-white text-[10px] font-black uppercase tracking-widest rounded-xl border border-neutral-700 transition active:scale-95"
                    >
                        Install
                    </button>
                </div>
            </div>
        </div>
    );
}

function InstalledItem({ item, onAction }) {
    const isDirectory = Boolean(item.isDirectory);
    
    return (
        <div className="bg-neutral-900 border border-neutral-800 rounded-3xl p-5 mb-4 group hover:border-neutral-700 transition-all shadow-xl shadow-black/10">
            <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-width-0">
                    <div className="flex items-center gap-2 mb-1">
                        <i className={`bi ${isDirectory ? 'bi-folder2-open' : 'bi-file-earmark-zip'} text-primary-400 text-lg`}></i>
                        <h4 className="text-sm font-black text-white uppercase tracking-tight truncate">{item.name}</h4>
                    </div>
                    <p className="text-[10px] text-neutral-500 font-mono truncate opacity-60 mb-3">{item.path}</p>
                    
                    <div className="flex flex-wrap gap-2 mb-4">
                        {item.tracked && <span className="px-2 py-0.5 rounded-lg bg-emerald-600/10 text-emerald-500 text-[9px] font-black uppercase border border-emerald-900/30">Tracked</span>}
                        {item.updateAvailable && <span className="px-2 py-0.5 rounded-lg bg-amber-600/10 text-amber-500 text-[9px] font-black uppercase border border-amber-900/30">Update Available</span>}
                        {item.drifted && <span className="px-2 py-0.5 rounded-lg bg-rose-600/10 text-rose-500 text-[9px] font-black uppercase border border-rose-900/30">Drifted</span>}
                        <span className="px-2 py-0.5 rounded-lg bg-neutral-800 text-neutral-400 text-[9px] font-black uppercase">{formatBytes(item.size)}</span>
                    </div>
                </div>
                
                <div className="flex gap-2">
                    {!isDirectory && item.canUpdate && (
                        <button 
                            onClick={() => onAction('update', item)}
                            className="w-10 h-10 flex items-center justify-center bg-blue-600/10 text-blue-500 rounded-xl hover:bg-blue-600 hover:text-white transition active:scale-95 shadow-lg shadow-blue-900/10"
                            title="Update to latest"
                        >
                            <i className="bi bi-arrow-repeat"></i>
                        </button>
                    )}
                    <button 
                        onClick={() => onAction('delete', item)}
                        className="w-10 h-10 flex items-center justify-center bg-rose-600/10 text-rose-500 rounded-xl hover:bg-rose-600 hover:text-white transition active:scale-95 shadow-lg shadow-rose-900/10"
                        title="Delete addon"
                    >
                        <i className="bi bi-trash3"></i>
                    </button>
                </div>
            </div>
        </div>
    );
}

export function ServerMinecraftAddonsPage({ pageData = data }) {
    const server = pageData.server || {};
    const defaults = pageData.minecraftDefaults || {};
    const catalog = pageData.minecraftCatalog || {};
    
    const [search, setSearch] = useState('');
    const [kind, setKind] = useState(defaults.kind || 'plugin');
    const [results, setResults] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [view, setView] = useState('browse'); // 'browse' or 'installed'
    const [installed, setInstalled] = useState([]);
    const [loadingInstalled, setLoadingInstalled] = useState(false);

    // Filters from EJS logic
    const [loader, setLoader] = useState(defaults.loader || '');
    const [mcVersion, setMcVersion] = useState(defaults.version || '');
    const [targetDir, setTargetDir] = useState(defaults.targetDirectory || (kind === 'plugin' ? 'plugins' : 'mods'));

    // Direct Download State
    const [directUrl, setDirectUrl] = useState('');
    const [directName, setDirectName] = useState('');
    const [directExtract, setDirectExtract] = useState(false);

    const loaderOptions = useMemo(() => {
        const key = kind === 'plugin' ? 'plugins' : (kind === 'mod' ? 'mods' : (kind === 'datapack' ? 'datapacks' : (kind === 'resourcepack' ? 'resourcepacks' : 'worlds')));
        return catalog[key] || [];
    }, [kind, catalog]);

    useEffect(() => {
        if (view !== 'browse') return;
        
        let cancelled = false;
        const timer = setTimeout(() => {
            setLoading(true);
            setError('');
            const params = new URLSearchParams({
                q: search,
                kind,
                loader,
                version: mcVersion,
                limit: 12
            });
            
            fetch(`/server/${server.containerId}/minecraft/addons/search?${params.toString()}`)
                .then(res => res.json())
                .then(payload => {
                    if (cancelled) return;
                    if (payload.success) {
                        setResults(payload.projects || []);
                    } else {
                        throw new Error(payload.error || 'Failed to search modrinth');
                    }
                    setLoading(false);
                })
                .catch(err => {
                    if (cancelled) return;
                    console.error(err);
                    setError(err.message || 'Search failed');
                    setLoading(false);
                });
        }, 500);

        return () => {
            cancelled = true;
            clearTimeout(timer);
        };
    }, [search, kind, loader, mcVersion, view, server.containerId]);

    const fetchInstalled = () => {
        setLoadingInstalled(true);
        fetch(`/server/${server.containerId}/minecraft/addons/installed?directory=${encodeURIComponent(targetDir)}`)
            .then(res => res.json())
            .then(payload => {
                if (payload.success) {
                    setInstalled(payload.items || []);
                }
                setLoadingInstalled(false);
            })
            .catch(() => setLoadingInstalled(false));
    };

    useEffect(() => {
        if (view === 'installed') {
            fetchInstalled();
        }
    }, [view, targetDir]);

    const handleInstall = (project) => {
        if (confirm(`Install ${project.title}?`)) {
            const params = new URLSearchParams({
                projectId: project.id,
                kind,
                loader,
                gameVersion: mcVersion,
                targetDirectory: targetDir
            });
            window.location.href = `/server/${server.containerId}/minecraft/addons/install?${params.toString()}`;
        }
    };

    const handleDirectDownload = () => {
        if (!directUrl) return;
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = `/server/${server.containerId}/minecraft/addons/download-url`;
        
        const inputs = {
            url: directUrl,
            fileName: directName,
            targetDirectory: targetDir,
            extract: directExtract ? 'true' : 'false'
        };
        
        Object.entries(inputs).forEach(([k, v]) => {
            const input = document.createElement('input');
            input.name = k;
            input.value = v;
            form.appendChild(input);
        });
        
        document.body.appendChild(form);
        form.submit();
    };

    const handleAction = (action, item) => {
        if (action === 'delete') {
            if (confirm(`Are you sure you want to delete ${item.name}?`)) {
                fetch(`/server/${server.containerId}/minecraft/addons/delete`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: item.path })
                }).then(() => fetchInstalled());
            }
        } else if (action === 'update') {
            // Logic for update...
        }
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Minecraft Addons">
            <PageContentBlock 
                title="Addons Center" 
                description={`Manage mods, plugins, and resource packs for your ${server.name} server.`}
                eyebrow="Minecraft Management"
            >
                <div className="flex bg-neutral-900 border border-neutral-800 rounded-3xl p-1 gap-1 mb-8 w-fit shadow-2xl shadow-black/20">
                    <button 
                        onClick={() => setView('browse')}
                        className={`px-8 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all flex items-center gap-2 ${view === 'browse' ? 'bg-primary-600 text-white shadow-lg shadow-primary-900/20' : 'text-neutral-500 hover:text-neutral-300'}`}
                    >
                        <i className="bi bi-search"></i> Browse
                    </button>
                    <button 
                        onClick={() => setView('installed')}
                        className={`px-8 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all flex items-center gap-2 ${view === 'installed' ? 'bg-primary-600 text-white shadow-lg shadow-primary-900/20' : 'text-neutral-500 hover:text-neutral-300'}`}
                    >
                        <i className="bi bi-archive"></i> Installed
                    </button>
                </div>

                {view === 'browse' ? (
                    <>
                        <div className="bg-neutral-900 border border-neutral-800 rounded-[2.5rem] p-8 mb-12 shadow-2xl shadow-black/40">
                            <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-end">
                                <div className="xl:col-span-4">
                                    <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-3 ml-1">Type</label>
                                    <div className="flex bg-neutral-950/50 border border-neutral-800 rounded-2xl p-1 gap-1">
                                        {['plugin', 'mod', 'datapack'].map(k => (
                                            <button 
                                                key={k}
                                                onClick={() => setKind(k)}
                                                className={`flex-1 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all ${kind === k ? 'bg-neutral-800 text-white shadow-inner shadow-black/50' : 'text-neutral-600 hover:text-neutral-400'}`}
                                            >
                                                {k}s
                                            </button>
                                        ))}
                                    </div>
                                </div>
                                <div className="xl:col-span-2">
                                    <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-3 ml-1">Loader</label>
                                    <select 
                                        value={loader} 
                                        onChange={(e) => setLoader(e.target.value)}
                                        className="w-full bg-neutral-950/50 border border-neutral-800 rounded-2xl px-4 py-3 text-[11px] font-bold text-white focus:outline-none focus:border-primary-500/50 transition-colors uppercase tracking-widest"
                                    >
                                        <option value="">Any Loader</option>
                                        {loaderOptions.map(opt => <option key={opt} value={opt}>{opt}</option>)}
                                    </select>
                                </div>
                                <div className="xl:col-span-2">
                                    <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-3 ml-1">Minecraft</label>
                                    <input 
                                        type="text" 
                                        placeholder="1.20.1" 
                                        value={mcVersion}
                                        onChange={(e) => setMcVersion(e.target.value)}
                                        className="w-full bg-neutral-950/50 border border-neutral-800 rounded-2xl px-4 py-3 text-[11px] font-bold text-white focus:outline-none focus:border-primary-500/50 transition-colors placeholder:text-neutral-700 font-mono" 
                                    />
                                </div>
                                <div className="xl:col-span-4">
                                    <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-3 ml-1">Live Search</label>
                                    <div className="relative">
                                        <i className="bi bi-search absolute left-4 top-1/2 -translate-y-1/2 text-neutral-600"></i>
                                        <input 
                                            type="text" 
                                            placeholder="Find projects on Modrinth..." 
                                            value={search}
                                            onChange={(e) => setSearch(e.target.value)}
                                            className="w-full bg-neutral-950 border border-neutral-800 rounded-2xl py-3 pl-11 pr-4 text-sm text-white focus:outline-none focus:border-primary-500/50 transition-all font-medium"
                                        />
                                    </div>
                                </div>
                            </div>
                        </div>

                        {error && (
                            <div className="bg-rose-600/10 border border-rose-600/20 text-rose-500 p-6 rounded-3xl mb-12 flex items-center gap-4 animate-in fade-in slide-in-from-top-4">
                                <i className="bi bi-exclamation-octagon text-2xl"></i>
                                <span className="font-bold uppercase tracking-widest text-xs">{error}</span>
                            </div>
                        )}

                        {loading ? (
                            <div className="flex flex-col items-center justify-center py-32 gap-6">
                                <div className="w-16 h-16 border-4 border-neutral-800 border-t-primary-500 rounded-full animate-spin shadow-2xl shadow-primary-900/20"></div>
                                <span className="text-[10px] font-black text-neutral-500 uppercase tracking-[0.4em] animate-pulse">Querying Catalog</span>
                            </div>
                        ) : (
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                                {results.length > 0 ? (
                                    results.map((project) => (
                                        <AddonCard key={project.project_id} project={project} onInstall={handleInstall} />
                                    ))
                                ) : (
                                    <div className="col-span-full py-32 text-center opacity-40">
                                        <i className="bi bi-cloud-slash text-6xl mb-6 block"></i>
                                        <h3 className="text-xl font-black uppercase tracking-widest text-neutral-500">No results</h3>
                                        <p className="text-xs font-bold text-neutral-600 uppercase mt-2 tracking-widest">Adjust filters or search terms</p>
                                    </div>
                                )}
                            </div>
                        )}

                        <div className="mt-24 border-t border-neutral-800 pt-16">
                            <h3 className="text-lg font-black text-white uppercase tracking-tight mb-2 flex items-center gap-3">
                                <i className="bi bi-cloud-download text-primary-500 text-2xl"></i> Direct URL Download
                            </h3>
                            <p className="text-sm text-neutral-500 font-medium mb-8">Install custom archives or specific builds by providing a direct link.</p>
                            
                            <div className="bg-neutral-900 border border-neutral-800 rounded-[2.5rem] p-8 shadow-2xl shadow-black/20">
                                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-end">
                                    <div className="lg:col-span-5">
                                        <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-3 ml-1">Resource URL</label>
                                        <input 
                                            type="text" 
                                            placeholder="https://example.com/mod.jar" 
                                            value={directUrl}
                                            onChange={(e) => setDirectUrl(e.target.value)}
                                            className="w-full bg-neutral-950 border border-neutral-800 rounded-2xl py-3 px-4 text-sm text-white focus:outline-none focus:border-primary-500/50 transition-all font-mono" 
                                        />
                                    </div>
                                    <div className="lg:col-span-3">
                                        <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-3 ml-1">Custom Name (Opt.)</label>
                                        <input 
                                            type="text" 
                                            placeholder="world.zip" 
                                            value={directName}
                                            onChange={(e) => setDirectName(e.target.value)}
                                            className="w-full bg-neutral-950 border border-neutral-800 rounded-2xl py-3 px-4 text-sm text-white focus:outline-none focus:border-primary-500/50 transition-all font-medium" 
                                        />
                                    </div>
                                    <div className="lg:col-span-2">
                                        <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 ml-1">Post Actions</label>
                                        <label className="flex items-center gap-3 cursor-pointer group">
                                            <input 
                                                type="checkbox" 
                                                checked={directExtract}
                                                onChange={(e) => setDirectExtract(e.target.checked)}
                                                className="w-5 h-5 rounded-lg bg-neutral-950 border-neutral-800 checked:bg-primary-600" 
                                            />
                                            <span className="text-[10px] font-black text-neutral-600 uppercase tracking-widest group-hover:text-neutral-400 transition-colors">Extract</span>
                                        </label>
                                    </div>
                                    <div className="lg:col-span-2">
                                        <button 
                                            onClick={handleDirectDownload}
                                            disabled={!directUrl}
                                            className={`w-full py-3 rounded-2xl text-[10px] font-black uppercase tracking-[0.2em] transition-all shadow-xl active:scale-95 ${!directUrl ? 'bg-neutral-800 text-neutral-600' : 'bg-primary-600 hover:bg-primary-500 text-white shadow-primary-900/20'}`}
                                        >
                                            Fetch File
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </>
                ) : (
                    <div className="animate-in fade-in slide-in-from-left-4 duration-500">
                        <div className="flex flex-col md:flex-row items-center justify-between gap-6 mb-12">
                            <div>
                                <h3 className="text-xl font-black text-white uppercase tracking-tight mb-1">Installed Inventory</h3>
                                <p className="text-xs text-neutral-500 font-bold uppercase tracking-widest">Scanning folder: {targetDir}</p>
                            </div>
                            <div className="flex gap-3">
                                <button 
                                    onClick={fetchInstalled}
                                    className="px-6 py-3 bg-neutral-900 border border-neutral-800 hover:bg-neutral-800 text-white text-[10px] font-black uppercase tracking-widest rounded-2xl transition active:scale-95 flex items-center gap-2"
                                >
                                    <i className="bi bi-arrow-clockwise text-primary-500"></i> Rescan
                                </button>
                                <select 
                                    className="bg-neutral-900 border border-neutral-800 text-white text-[10px] font-black uppercase tracking-widest rounded-2xl px-6 py-3 focus:outline-none focus:border-primary-500/50"
                                    value={targetDir}
                                    onChange={(e) => setTargetDir(e.target.value)}
                                >
                                    <option value="plugins">/plugins</option>
                                    <option value="mods">/mods</option>
                                    <option value="datapacks">/datapacks</option>
                                    <option value="resourcepacks">/resourcepacks</option>
                                    <option value=".">Root (/) </option>
                                </select>
                            </div>
                        </div>

                        {loadingInstalled ? (
                            <div className="flex flex-col items-center justify-center py-32 gap-6 opacity-40">
                                <div className="w-12 h-12 border-4 border-neutral-800 border-t-primary-500 rounded-full animate-spin"></div>
                                <span className="text-[10px] font-black uppercase tracking-[0.3em]">Browsing Filesystem...</span>
                            </div>
                        ) : (
                            <div className="max-w-4xl mx-auto">
                                {installed.length > 0 ? (
                                    installed.map((item, idx) => (
                                        <InstalledItem key={idx} item={item} onAction={handleAction} />
                                    ))
                                ) : (
                                    <div className="py-32 text-center opacity-40 bg-neutral-950/50 border-2 border-dashed border-neutral-900 rounded-[3rem]">
                                        <i className="bi bi-archive text-6xl mb-6 block"></i>
                                        <h3 className="text-xl font-black uppercase tracking-widest text-neutral-600">Empty Directory</h3>
                                        <p className="text-[10px] font-bold text-neutral-700 uppercase mt-2 tracking-widest">No matching assets found in {targetDir}</p>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerMinecraftAddonsPage;

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <BrowserRouter>
            <ServerMinecraftAddonsPage pageData={data} />
        </BrowserRouter>
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}