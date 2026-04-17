import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-minecraft-addons';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

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
                <p className="text-xs text-neutral-500 leading-relaxed line-clamp-3 mb-6 flex-1">{project.description}</p>
                <div className="flex items-center justify-between mt-auto">
                    <div className="flex items-center gap-2">
                        <i className="bi bi-download text-neutral-600"></i>
                        <span className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest">{Math.round(project.downloads / 1000)}K DLs</span>
                    </div>
                    <button 
                        onClick={() => onInstall(project)}
                        className="px-4 py-2 bg-neutral-800 hover:bg-neutral-700 text-white text-[10px] font-black uppercase tracking-widest rounded-xl border border-neutral-700 transition"
                    >
                        View Details
                    </button>
                </div>
            </div>
        </div>
    );
}

export function ServerMinecraftAddonsPage({ pageData = data }) {
    const server = pageData.server || {};
    const defaults = pageData.minecraftDefaults || {};
    
    const [search, setSearch] = useState('');
    const [kind, setKind] = useState(defaults.kind || 'mod');
    const [results, setResults] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    useEffect(() => {
        let cancelled = false;
        const timer = setTimeout(() => {
            setLoading(true);
            setError('');
            fetch(`/server/${server.containerId}/minecraft/addons/search?q=${encodeURIComponent(search)}&kind=${kind}&limit=12`)
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
    }, [search, kind, server.containerId]);

    return (
        <ReactAppShell pageData={pageData} subtitle="Addons">
            <PageContentBlock 
                title="Addons Hub" 
                description={`Browse and install thousands of mods and plugins for your ${server.name} instance.`}
                eyebrow="Resource Catalog"
            >
                <div className="flex flex-col md:flex-row gap-6 mb-12">
                    <div className="flex-1 relative">
                        <i className="bi bi-search absolute left-5 top-1/2 -translate-y-1/2 text-neutral-600 text-lg"></i>
                        <input 
                            type="text" 
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            placeholder="Search Modrinth (e.g. WorldEdit, Essentials, Sodium)..."
                            className="w-full bg-neutral-900 border border-neutral-800 rounded-3xl py-5 pl-14 pr-6 text-white text-sm focus:outline-none focus:border-primary-500/50 shadow-2xl shadow-black/20"
                        />
                    </div>
                    <div className="flex bg-neutral-900 border border-neutral-800 rounded-3xl p-1 gap-1">
                        <button 
                            onClick={() => setKind('mod')}
                            className={`px-8 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all ${kind === 'mod' ? 'bg-primary-600 text-white shadow-lg shadow-primary-900/20' : 'text-neutral-500 hover:text-neutral-300'}`}
                        >
                            Mods
                        </button>
                        <button 
                            onClick={() => setKind('plugin')}
                            className={`px-8 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all ${kind === 'plugin' ? 'bg-primary-600 text-white shadow-lg shadow-primary-900/20' : 'text-neutral-500 hover:text-neutral-300'}`}
                        >
                            Plugins
                        </button>
                    </div>
                </div>

                {error && (
                    <div className="bg-rose-600/10 border border-rose-600/30 text-rose-400 p-6 rounded-3xl mb-8 flex items-center gap-4">
                        <i className="bi bi-exclamation-triangle text-2xl"></i>
                        <span className="font-bold uppercase tracking-widest text-sm">{error}</span>
                    </div>
                )}

                {loading ? (
                    <div className="flex flex-col items-center justify-center py-24 gap-6">
                        <div className="w-16 h-16 border-4 border-neutral-800 border-t-primary-500 rounded-full animate-spin"></div>
                        <span className="text-xs font-black text-neutral-500 uppercase tracking-[0.3em] pulse">Indexing Modrinth...</span>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                        {results.length > 0 ? (
                            results.map((project) => (
                                <AddonCard key={project.project_id} project={project} onInstall={(p) => window.location.href = `/server/${server.containerId}/minecraft/addons/project/${p.project_id}`} />
                            ))
                        ) : (
                            <div className="col-span-full py-24 text-center">
                                <i className="bi bi-search text-6xl text-neutral-800 mb-6 block"></i>
                                <div className="text-lg font-bold text-neutral-600 uppercase tracking-widest">No addons found</div>
                                <p className="text-sm text-neutral-700 mt-2">Try adjusting your search terms or filters.</p>
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
    root.render(<ServerMinecraftAddonsPage pageData={data} />);
}
