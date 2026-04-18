import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Link } from 'react-router-dom';
import { ReactRoutes } from './ReactRoutes.js';
import { ThemeProvider } from './components/ThemeContext.jsx';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import { useTheme } from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'themes';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ThemesPage({ pageData = data }) {
    const themeCatalog = Array.isArray(pageData.themeCatalog) ? pageData.themeCatalog : [];
    const { activeTheme, previewTheme, customTheme, applyTheme, toggleCustomTheme, restoreTheme } = useTheme();
    
    const handleApply = (themeId) => {
        // Form submission for real application (server-side persistence)
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/themes/apply';
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'theme';
        input.value = themeId;
        form.appendChild(input);
        document.body.appendChild(form);
        form.submit();
    };

    const handleToggleCustom = (enabled) => {
        // Form submission for real application
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/themes/custom-mode';
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'enabled';
        input.value = String(enabled);
        form.appendChild(input);
        document.body.appendChild(form);
        form.submit();
    };

    const handlePreview = (theme) => {
        if (previewTheme === theme.id) {
            restoreTheme();
        } else {
            applyTheme(theme.id, true);
        }
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Themes & Styling">
            <PageContentBlock 
                title="Themes" 
                description="Pick a preset theme or manage your private custom theme override."
                actions={
                    <div className="flex gap-2">
                        <a href="/themes/builder" className="bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2">
                            <i className="bi bi-sliders"></i> Builder
                        </a>
                        <Link to={ReactRoutes.account} className="bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2">
                            <i className="bi bi-arrow-left"></i> Account
                        </Link>
                    </div>
                }
            >
                {/* Active Status Card */}
                <div className="bg-neutral-800 border border-neutral-700 rounded-xl p-6 mb-8 shadow-sm">
                    <div className="flex flex-wrap justify-between items-center gap-6">
                        <div className="flex gap-8">
                            <div>
                                <span className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1">Base Theme</span>
                                <div className="text-xl font-bold text-white capitalize">{activeTheme}</div>
                            </div>
                            <div>
                                <span className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1">Custom Override</span>
                                <div className="flex items-center gap-2">
                                    <div className={`w-2 h-2 rounded-full ${customTheme.enabled ? 'bg-green-500 animate-pulse' : 'bg-neutral-600'}`}></div>
                                    <span className={`text-sm font-bold ${customTheme.enabled ? 'text-green-400' : 'text-neutral-500'}`}>
                                        {customTheme.enabled ? 'ENABLED' : 'DISABLED'}
                                    </span>
                                </div>
                            </div>
                        </div>
                        
                        <div className="flex items-center gap-3">
                            <button 
                                onClick={() => handleToggleCustom(!customTheme.enabled)}
                                className={`px-4 py-2 rounded text-xs font-bold transition-all border ${customTheme.enabled ? 'bg-red-500/10 border-red-500/20 text-red-400 hover:bg-red-500/20' : 'bg-green-500/10 border-green-500/20 text-green-400 hover:bg-green-500/20'}`}
                            >
                                {customTheme.enabled ? 'Disable Override' : 'Enable Override'}
                            </button>
                        </div>
                    </div>
                    
                    {previewTheme && (
                        <div className="mt-6 pt-6 border-t border-neutral-700/50 flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                <i className="bi bi-eye-fill text-yellow-500"></i>
                                <span className="text-sm text-neutral-300">
                                    Currently previewing a theme. Styles are temporary.
                                </span>
                            </div>
                            <button 
                                onClick={restoreTheme}
                                className="text-xs font-bold text-yellow-500 hover:text-yellow-400 uppercase tracking-wider underline underline-offset-4"
                            >
                                Reset View
                            </button>
                        </div>
                    )}
                </div>

                {/* Theme Catalog */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {themeCatalog.map((theme) => {
                        const isCurrent = String(activeTheme).toLowerCase() === String(theme.id).toLowerCase();
                        const isPreviewing = previewTheme === theme.id;
                        const preview = theme.preview || {};
                        const swatches = Array.isArray(preview.swatches) ? preview.swatches : ['#3b82f6', '#2e3036', '#ffffff'];

                        return (
                            <div key={theme.id} className={`group bg-neutral-800 border rounded-2xl overflow-hidden transition-all duration-300 hover:translate-y-[-4px] hover:shadow-xl ${isCurrent ? 'border-primary-500 ring-1 ring-primary-500/20' : 'border-neutral-700'}`}>
                                {/* Card Header / Showcase */}
                                <div className="h-40 relative p-6 flex flex-col justify-end overflow-hidden" style={{ background: preview.background || 'linear-gradient(145deg, #1a1a20 0%, #0b0b0d 100%)' }}>
                                    <div className="absolute top-0 right-0 p-4 opacity-20 group-hover:scale-110 transition-transform">
                                        <i className="bi bi-palette2 text-8xl text-white"></i>
                                    </div>
                                    <div className="relative z-10 flex flex-col gap-1">
                                        <span className="text-[10px] font-black text-white/50 uppercase tracking-widest">{preview.eyebrow || 'PRESET'}</span>
                                        <h3 className="text-lg font-bold text-white leading-tight">{theme.label}</h3>
                                    </div>
                                    <div className="absolute right-6 bottom-6 flex flex-col gap-2">
                                        {swatches.map((color, idx) => (
                                            <div key={idx} className="w-8 h-8 rounded-lg border border-white/20 shadow-lg" style={{ backgroundColor: color }}></div>
                                        ))}
                                    </div>
                                </div>

                                {/* Card Body */}
                                <div className="p-5 flex flex-col gap-4">
                                    <div className="flex items-start justify-between">
                                        <p className="text-sm text-neutral-400 line-clamp-2 pr-4">{preview.summary || 'Custom theme profile for CPanel Rocky surface.'}</p>
                                        {isCurrent && (
                                            <span className="shrink-0 bg-primary-500/10 text-primary-400 border border-primary-500/20 text-[10px] font-black px-2 py-0.5 rounded">ACTIVE</span>
                                        )}
                                    </div>

                                    <div className="flex items-center gap-2 mt-auto">
                                        <button 
                                            onClick={() => handlePreview(theme)}
                                            className={`flex-1 text-xs font-bold py-2 rounded border transition-all ${isPreviewing ? 'bg-yellow-500/20 border-yellow-500/40 text-yellow-400' : 'bg-neutral-900 border-neutral-700 text-neutral-400 hover:text-white hover:border-neutral-600'}`}
                                        >
                                            <i className={`bi ${isPreviewing ? 'bi-eye-slash' : 'bi-eye'} mr-2`}></i>
                                            {isPreviewing ? 'Stop Preview' : 'Preview'}
                                        </button>
                                        <button 
                                            onClick={() => handleApply(theme.id)}
                                            disabled={isCurrent}
                                            className="flex-1 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-bold py-2 rounded shadow-sm transition-all"
                                        >
                                            <i className="bi bi-check2 mr-2"></i>Apply
                                        </button>
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ThemesPage;

if (root) {
    root.render(
        <BrowserRouter>
            <ThemeProvider pageData={data}>
                <ThemesPage pageData={data} />
            </ThemeProvider>
        </BrowserRouter>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
