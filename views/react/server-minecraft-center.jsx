import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-minecraft-center';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function MinecraftToolCard({ title, description, icon, href, colorClass }) {
    return (
        <a 
            href={href} 
            className="group relative bg-neutral-900 border border-neutral-800 rounded-3xl p-6 transition-all duration-300 hover:border-primary-500/50 hover:shadow-2xl hover:shadow-primary-900/10 hover:translate-y-[-4px]"
        >
            <div className={`w-14 h-14 rounded-2xl ${colorClass} flex items-center justify-center text-2xl mb-6 shadow-lg transition-transform group-hover:scale-110 duration-500`}>
                <i className={`bi ${icon}`}></i>
            </div>
            <div>
                <h3 className="text-lg font-black text-white mb-2 uppercase tracking-tight">{title}</h3>
                <p className="text-sm text-neutral-500 leading-relaxed font-medium">{description}</p>
            </div>
            <div className="absolute top-6 right-6 opacity-0 group-hover:opacity-100 transition-opacity">
                <i className="bi bi-arrow-up-right text-primary-500"></i>
            </div>
        </a>
    );
}

export function ServerMinecraftCenterPage({ pageData = data }) {
    const server = pageData.server || {};
    
    const tools = [
        {
            title: "Addons",
            description: "Browse and install thousands of Mods and Plugins from Modrinth.",
            icon: "bi-box",
            href: `/server/${server.containerId}/minecraft/addons`,
            colorClass: "bg-blue-600/10 text-blue-500"
        },
        {
            title: "World Center",
            description: "Advanced world management: Swap, clone, backup, or prune dimensions.",
            icon: "bi-globe-americas",
            href: `/server/${server.containerId}/minecraft/world-center`,
            colorClass: "bg-emerald-600/10 text-emerald-500"
        },
        {
            title: "Minecraft Control",
            description: "Manage server.properties, MOTD, whitelist, and essential rules.",
            icon: "bi-controller",
            href: `/server/${server.containerId}/minecraft/configs`,
            colorClass: "bg-amber-600/10 text-amber-500"
        },
        {
            title: "Admin & Players",
            description: "Inspect players, manage bans, chat, and server security permissions.",
            icon: "bi-shield-check",
            href: `/server/${server.containerId}/minecraft/admin`,
            colorClass: "bg-rose-600/10 text-rose-500"
        },
        {
            title: "Proxy Network",
            description: "Configuration for BungeeCord and Velocity proxy environments.",
            icon: "bi-diagram-3",
            href: `/server/${server.containerId}/minecraft/proxy`,
            colorClass: "bg-purple-600/10 text-purple-500"
        },
        {
            title: "Advanced Metrics",
            description: "TPS, MSPT, and real-time performance analytics for your Minecraft instance.",
            icon: "bi-bar-chart",
            href: `/server/${server.containerId}/minecraft/metrics`,
            colorClass: "bg-sky-600/10 text-sky-500"
        }
    ];

    return (
        <ReactAppShell pageData={pageData} subtitle="Minecraft Center">
            <PageContentBlock 
                title="Minecraft Center" 
                description={`Specialized tools and management for ${server.name}.`}
                eyebrow="Game Management"
            >
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {tools.map((tool, idx) => (
                        <MinecraftToolCard key={idx} {...tool} />
                    ))}
                </div>

                <div className="mt-12 bg-neutral-900 border border-neutral-800 rounded-3xl p-8 flex flex-col md:flex-row items-center justify-between gap-6">
                    <div className="flex items-center gap-6">
                        <div className="w-16 h-16 rounded-2xl bg-primary-600/10 flex items-center justify-center text-3xl text-primary-500">
                            <i className="bi bi-info-circle"></i>
                        </div>
                        <div>
                            <h4 className="text-xl font-black text-white mb-1 uppercase">Version Installer</h4>
                            <p className="text-sm text-neutral-500">Looking to switch Minecraft versions? Use the automated installer to deploy new builds.</p>
                        </div>
                    </div>
                    <a 
                        href={`/server/${server.containerId}/minecraft/installer`}
                        className="px-8 py-3 bg-neutral-100 hover:bg-white text-neutral-950 font-black uppercase tracking-widest rounded-xl transition-all shadow-xl shadow-white/5 active:scale-95 text-sm"
                    >
                        Open Installer
                    </a>
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerMinecraftCenterPage;

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <BrowserRouter>
            <ServerMinecraftCenterPage pageData={data} />
        </BrowserRouter>
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}