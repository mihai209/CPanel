import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ThemeProvider from './components/ThemeContext.jsx';
import ReactAppShell from './components/ReactAppShell';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-ai';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export default function ServerAiPage({ pageData = {} }) {
    const { server = {}, aiPolicy: policy = {}, aiAdminEnabled = false } = pageData;
    const [loading, setLoading] = useState(false);
    const [status, setStatus] = useState({ 
        type: pageData.error ? 'error' : (pageData.success ? 'success' : 'idle'), 
        message: pageData.error || pageData.success || '' 
    });

    const [formData, setFormData] = useState({
        enabled: !!policy.enabled,
        allowStart: !!policy.allowStart,
        allowStop: !!policy.allowStop,
        allowRestart: !!policy.allowRestart
    });

    const handleToggle = (key) => {
        setFormData(prev => ({ ...prev, [key]: !prev[key] }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setStatus({ type: 'idle', message: '' });

        try {
            const params = new URLSearchParams();
            if (formData.enabled) params.append('aiEnabled', 'true');
            if (formData.allowStart) params.append('aiAllowStart', 'true');
            if (formData.allowStop) params.append('aiAllowStop', 'true');
            if (formData.allowRestart) params.append('aiAllowRestart', 'true');

            const res = await fetch(`/server/${server.containerId}/ai-manage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: params
            });

            if (res.redirected) {
                window.location.href = res.url;
                return;
            }

            const data = await res.json();
            if (!res.ok || data.error) throw new Error(data.error || 'Failed to save AI policy');
            
            setStatus({ type: 'success', message: 'AI management policy updated successfully.' });
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
        } finally {
            setLoading(false);
        }
    };

    const Toggle = ({ label, helper, checked, onChange, disabled }) => (
        <label className={`flex items-center justify-between p-4 rounded-xl border transition-all select-none ${
            disabled ? 'opacity-50 cursor-not-allowed bg-neutral-950/20 border-neutral-800' : 'cursor-pointer bg-neutral-950/50 border-neutral-800 hover:border-neutral-700'
        }`}>
            <div className="flex flex-col gap-0.5">
                <span className="text-sm font-bold text-neutral-200">{label}</span>
                {helper && <span className="text-[10px] text-neutral-500 font-medium uppercase tracking-tighter">{helper}</span>}
            </div>
            <div className="relative">
                <input type="checkbox" checked={checked} onChange={e => !disabled && onChange(e.target.checked)} className="sr-only" disabled={disabled} />
                <div className={`w-10 h-5 rounded-full transition-colors ${checked ? 'bg-primary-500' : 'bg-neutral-800'}`}>
                    <div className={`absolute top-1 left-1 w-3 h-3 bg-white rounded-full transition-transform ${checked ? 'translate-x-5' : ''}`}></div>
                </div>
            </div>
        </label>
    );

    return (
        <ReactAppShell pageData={pageData} subtitle="AI Management">
            <form onSubmit={handleSubmit} className="max-w-3xl mx-auto space-y-6 pb-24">
                {/* ── Status Messages ─────────────────────────────────── */}
                {status.message && (
                    <div className={`p-4 rounded-xl border flex items-center gap-3 animate-in fade-in slide-in-from-top-2 duration-300 ${
                        status.type === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-400' : 
                        status.type === 'success' ? 'bg-green-500/10 border-green-500/20 text-green-400' : 
                        'bg-blue-500/10 border-blue-500/20 text-blue-400'
                    }`}>
                        <i className={`bi ${status.type === 'error' ? 'bi-exclamation-triangle-fill' : status.type === 'success' ? 'bi-check-circle-fill' : 'bi-info-circle-fill'}`}></i>
                        <span className="text-sm font-medium">{status.message}</span>
                    </div>
                )}

                {!aiAdminEnabled && (
                    <div className="p-4 bg-orange-500/10 border border-orange-500/20 rounded-xl flex items-center gap-3 text-orange-400">
                        <i className="bi bi-exclamation-triangle-fill"></i>
                        <span className="text-xs font-bold uppercase tracking-tight">AI agents are currently disabled globally by the system administrator.</span>
                    </div>
                )}

                <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 overflow-hidden shadow-sm">
                    <div className="px-6 py-4 bg-neutral-900/30 border-b border-neutral-800 flex items-center gap-3">
                        <i className="bi bi-robot text-primary-400"></i>
                        <h3 className="text-sm font-black text-neutral-500 uppercase tracking-widest">AI Policy & Governance</h3>
                    </div>
                    <div className="p-6 space-y-4">
                        <Toggle 
                            label="Enable AI Agent" 
                            helper="Users must also enable 'Experimental Features' in Account Settings"
                            checked={formData.enabled}
                            onChange={() => handleToggle('enabled')}
                            disabled={!aiAdminEnabled}
                        />

                        <div className="grid md:grid-cols-3 gap-3">
                            <Toggle 
                                label="Allow Start" 
                                helper="AI can power on"
                                checked={formData.allowStart}
                                onChange={() => handleToggle('allowStart')}
                                disabled={!aiAdminEnabled || !formData.enabled}
                            />
                            <Toggle 
                                label="Allow Stop" 
                                helper="AI can power off"
                                checked={formData.allowStop}
                                onChange={() => handleToggle('allowStop')}
                                disabled={!aiAdminEnabled || !formData.enabled}
                            />
                            <Toggle 
                                label="Allow Restart" 
                                helper="AI can reboot"
                                checked={formData.allowRestart}
                                onChange={() => handleToggle('allowRestart')}
                                disabled={!aiAdminEnabled || !formData.enabled}
                            />
                        </div>
                    </div>
                    <div className="px-6 py-4 bg-neutral-950/50 border-t border-neutral-800 flex items-center justify-between">
                        <p className="text-[10px] text-neutral-600 font-bold uppercase tracking-widest m-0">AI decisions are logged in the Activity tab.</p>
                        <button
                            type="submit"
                            disabled={loading || !aiAdminEnabled}
                            className="px-8 py-2 rounded-xl bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-800 text-white text-xs font-black uppercase tracking-widest transition-all shadow-lg shadow-primary-950/20"
                        >
                            {loading ? <i className="bi bi-arrow-repeat animate-spin me-2"></i> : <i className="bi bi-save me-2"></i>}
                            Save Policy
                        </button>
                    </div>
                </div>

                <div className="bg-blue-500/5 rounded-2xl border border-blue-500/10 p-6 flex gap-4">
                    <div className="w-10 h-10 rounded-full bg-blue-500/20 flex items-center justify-center shrink-0">
                        <i className="bi bi-info-circle-fill text-blue-400"></i>
                    </div>
                    <div className="space-y-2">
                        <h4 className="text-sm font-bold text-neutral-200">What are AI Agents?</h4>
                        <p className="text-xs text-neutral-400 leading-relaxed m-0">
                            Our AI agents use advanced LLMs to monitor console output and assist with troubleshooting. 
                            When enabled, the agent can recommend solutions for crashes, explain complex logs, and (if permitted) 
                            manage power states to resolve downtime automatically.
                        </p>
                    </div>
                </div>
            </form>
        </ReactAppShell>
    );
}

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <BrowserRouter>
                <ServerAiPage pageData={data} />
            </BrowserRouter>
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
