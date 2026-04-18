import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ThemeProvider from './components/ThemeContext.jsx';
import ReactAppShell from './components/ReactAppShell';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-smartalerts';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export default function ServerSmartAlertsPage({ pageData = {} }) {
    const { server = {}, smartAlerts: config = {} } = pageData;
    const [loading, setLoading] = useState(false);
    const [status, setStatus] = useState({ 
        type: pageData.error ? 'error' : (pageData.success ? 'success' : 'idle'), 
        message: pageData.error || pageData.success || '' 
    });

    const [formData, setFormData] = useState({
        enabled: !!config.enabled,
        discordWebhook: config.discordWebhook || '',
        telegramBotToken: config.telegramBotToken || '',
        telegramChatId: config.telegramChatId || '',
        events: {
            started: !!config.events?.started,
            stopped: !!config.events?.stopped,
            crashed: !!config.events?.crashed,
            reinstallSuccess: !!config.events?.reinstallSuccess,
            reinstallFailed: !!config.events?.reinstallFailed,
            suspended: !!config.events?.suspended,
            unsuspended: !!config.events?.unsuspended,
            resourceAnomaly: !!config.events?.resourceAnomaly,
            pluginConflict: !!config.events?.pluginConflict
        },
        anomaly: {
            enabled: !!config.anomaly?.enabled,
            cpuThreshold: config.anomaly?.cpuThreshold || 95,
            memoryThreshold: config.anomaly?.memoryThreshold || 90,
            diskThreshold: config.anomaly?.diskThreshold || 90,
            durationSamples: config.anomaly?.durationSamples || 3,
            cooldownSeconds: config.anomaly?.cooldownSeconds || 300
        },
        logCleanup: {
            enabled: !!config.logCleanup?.enabled,
            directory: config.logCleanup?.directory || '/logs',
            maxFileSizeMB: config.logCleanup?.maxFileSizeMB || 25,
            keepFiles: config.logCleanup?.keepFiles || 20,
            maxAgeDays: config.logCleanup?.maxAgeDays || 14,
            compressOld: !!config.logCleanup?.compressOld
        }
    });

    const [showTutorial, setShowTutorial] = useState(false);
    const [tutorialTab, setTutorialTab] = useState('discord');

    const handleToggle = (path, value) => {
        const parts = path.split('.');
        if (parts.length === 1) {
            setFormData({ ...formData, [parts[0]]: value });
        } else if (parts.length === 2) {
            setFormData({
                ...formData,
                [parts[0]]: { ...formData[parts[0]], [parts[1]]: value }
            });
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setStatus({ type: 'idle', message: '' });

        try {
            const params = new URLSearchParams();
            params.append('enabled', formData.enabled ? '1' : '0');
            params.append('discordWebhook', formData.discordWebhook);
            params.append('telegramBotToken', formData.telegramBotToken);
            params.append('telegramChatId', formData.telegramChatId);
            
            // Events
            Object.entries(formData.events).forEach(([k, v]) => {
                if (v) params.append(`event${k.charAt(0).toUpperCase() + k.slice(1)}`, '1');
            });

            // Anomaly
            params.append('anomalyEnabled', formData.anomaly.enabled ? '1' : '0');
            params.append('anomalyCpuThreshold', formData.anomaly.cpuThreshold);
            params.append('anomalyMemoryThreshold', formData.anomaly.memoryThreshold);
            params.append('anomalyDiskThreshold', formData.anomaly.diskThreshold);
            params.append('anomalyDurationSamples', formData.anomaly.durationSamples);
            params.append('anomalyCooldownSeconds', formData.anomaly.cooldownSeconds);

            // Cleanup
            params.append('logCleanupEnabled', formData.logCleanup.enabled ? '1' : '0');
            params.append('logCleanupDirectory', formData.logCleanup.directory);
            params.append('logCleanupMaxFileSizeMB', formData.logCleanup.maxFileSizeMB);
            params.append('logCleanupKeepFiles', formData.logCleanup.keepFiles);
            params.append('logCleanupMaxAgeDays', formData.logCleanup.maxAgeDays);
            params.append('logCleanupCompressOld', formData.logCleanup.compressOld ? '1' : '0');

            const res = await fetch(`/server/${server.containerId}/smartalerts`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: params
            });

            if (res.redirected) {
                window.location.href = res.url;
                return;
            }

            const data = await res.json();
            if (!res.ok || data.error) throw new Error(data.error || 'Failed to save settings');
            
            setStatus({ type: 'success', message: 'Smart Alert configuration updated successfully.' });
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
        } finally {
            setLoading(false);
        }
    };

    const Section = ({ title, icon, children }) => (
        <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 overflow-hidden shadow-sm">
            <div className="px-6 py-4 bg-neutral-900/30 border-b border-neutral-800 flex items-center gap-3">
                <i className={`bi ${icon} text-primary-400`}></i>
                <h3 className="text-sm font-black text-neutral-500 uppercase tracking-widest">{title}</h3>
            </div>
            <div className="p-6">
                {children}
            </div>
        </div>
    );

    const Toggle = ({ label, checked, onChange, helper }) => (
        <label className="flex items-center justify-between p-4 rounded-xl bg-neutral-950/50 border border-neutral-800 hover:border-neutral-700 transition-all cursor-pointer group">
            <div className="flex flex-col gap-0.5">
                <span className="text-sm font-bold text-neutral-200 group-hover:text-primary-400 transition-colors">{label}</span>
                {helper && <span className="text-[10px] text-neutral-500 font-medium uppercase tracking-tighter">{helper}</span>}
            </div>
            <div className="relative">
                <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} className="sr-only" />
                <div className={`w-10 h-5 rounded-full transition-colors ${checked ? 'bg-primary-500' : 'bg-neutral-800'}`}>
                    <div className={`absolute top-1 left-1 w-3 h-3 bg-white rounded-full transition-transform ${checked ? 'translate-x-5' : ''}`}></div>
                </div>
            </div>
        </label>
    );

    return (
        <ReactAppShell pageData={pageData} subtitle="Smart Alerts">
            <form onSubmit={handleSubmit} className="max-w-7xl mx-auto space-y-6 pb-24">
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

                <div className="grid lg:grid-cols-2 gap-6">
                    {/* ── Left Column: Config ────────────────────────────── */}
                    <div className="space-y-6">
                        <Section title="General State" icon="bi-broadcast-pin">
                            <Toggle 
                                label="Enable Smart Alerts" 
                                helper="Global dispatch for all integrations below"
                                checked={formData.enabled}
                                onChange={v => handleToggle('enabled', v)}
                            />
                        </Section>

                        <Section title="Discord Integration" icon="bi-discord">
                            <label className="block text-[10px] font-black text-neutral-600 uppercase tracking-widest mb-2 px-1">Webhook URL</label>
                            <input 
                                type="url" 
                                className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-3 text-sm text-neutral-300 focus:outline-none focus:border-primary-500/50"
                                placeholder="https://discord.com/api/webhooks/..."
                                value={formData.discordWebhook}
                                onChange={e => setFormData({...formData, discordWebhook: e.target.value})}
                            />
                        </Section>

                        <Section title="Telegram Integration" icon="bi-telegram">
                            <div className="grid md:grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <label className="block text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1">Bot Token</label>
                                    <input 
                                        type="text" 
                                        className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-3 text-sm text-neutral-300 focus:outline-none focus:border-primary-500/50"
                                        placeholder="123456:ABC..."
                                        value={formData.telegramBotToken}
                                        onChange={e => setFormData({...formData, telegramBotToken: e.target.value})}
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="block text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1">Chat ID</label>
                                    <input 
                                        type="text" 
                                        className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-3 text-sm text-neutral-300 focus:outline-none focus:border-primary-500/50"
                                        placeholder="-100..."
                                        value={formData.telegramChatId}
                                        onChange={e => setFormData({...formData, telegramChatId: e.target.value})}
                                    />
                                </div>
                            </div>
                        </Section>

                        <Section title="Event Subscriptions" icon="bi-lightning-charge-fill">
                            <div className="grid md:grid-cols-3 gap-3">
                                {Object.keys(formData.events).map(key => (
                                    <div key={key} onClick={() => handleToggle(`events.${key}`, !formData.events[key])} className={`p-3 rounded-xl border cursor-pointer transition-all flex flex-col items-center justify-center gap-2 text-center group ${
                                        formData.events[key] ? 'bg-primary-500/10 border-primary-500/30' : 'bg-neutral-950/30 border-neutral-800 hover:border-neutral-700'
                                    }`}>
                                        <i className={`bi bi-${formData.events[key] ? 'check-circle-fill text-primary-400' : 'circle text-neutral-700'}`}></i>
                                        <span className={`text-[9px] font-black uppercase tracking-widest ${formData.events[key] ? 'text-primary-400' : 'text-neutral-500'}`}>
                                            {key.replace(/([A-Z])/g, ' $1')}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </Section>
                    </div>

                    {/* ── Right Column: Automations ─────────────────────── */}
                    <div className="space-y-6">
                        <Section title="Anomaly Detection" icon="bi-activity">
                            <Toggle 
                                label="Automatic Spike Alerts" 
                                helper="Requires Monitoring Policy to be active"
                                checked={formData.anomaly.enabled}
                                onChange={v => handleToggle('anomaly.enabled', v)}
                            />
                            <div className="grid grid-cols-3 gap-3 mt-6">
                                {[
                                    { label: 'CPU %', key: 'cpuThreshold' },
                                    { label: 'RAM %', key: 'memoryThreshold' },
                                    { label: 'Disk %', key: 'diskThreshold' },
                                    { label: 'Samples', key: 'durationSamples' },
                                    { label: 'Cooldown', key: 'cooldownSeconds' }
                                ].map(item => (
                                    <div key={item.key} className="space-y-1.5">
                                        <label className="text-[9px] font-black text-neutral-600 uppercase tracking-widest px-1">{item.label}</label>
                                        <input 
                                            type="number" 
                                            value={formData.anomaly[item.key]} 
                                            onChange={e => handleToggle(`anomaly.${item.key}`, parseInt(e.target.value))}
                                            className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-neutral-300"
                                        />
                                    </div>
                                ))}
                            </div>
                        </Section>

                        <Section title="Log Rotation & Cleanup" icon="bi-trash-fill">
                            <Toggle 
                                label="Periodic Maintenance" 
                                helper="Automated cleanup of heavy log files"
                                checked={formData.logCleanup.enabled}
                                onChange={v => handleToggle('logCleanup.enabled', v)}
                            />
                            <div className="mt-6 space-y-4">
                                <div className="space-y-1.5">
                                    <label className="text-[9px] font-black text-neutral-600 uppercase tracking-widest px-1">Cleanup Path</label>
                                    <input 
                                        type="text" 
                                        value={formData.logCleanup.directory}
                                        onChange={e => handleToggle('logCleanup.directory', e.target.value)}
                                        className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2.5 text-sm text-neutral-300"
                                    />
                                </div>
                                <div className="grid grid-cols-3 gap-3">
                                    {[
                                        { label: 'Max File MB', key: 'maxFileSizeMB' },
                                        { label: 'Keep Files', key: 'keepFiles' },
                                        { label: 'Max Days', key: 'maxAgeDays' }
                                    ].map(item => (
                                        <div key={item.key} className="space-y-1.5">
                                            <label className="text-[9px] font-black text-neutral-600 uppercase tracking-widest px-1">{item.label}</label>
                                            <input 
                                                type="number" 
                                                value={formData.logCleanup[item.key]} 
                                                onChange={e => handleToggle(`logCleanup.${item.key}`, parseInt(e.target.value))}
                                                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-neutral-300"
                                            />
                                        </div>
                                    ))}
                                </div>
                                <Toggle 
                                    label="Gzip Compression" 
                                    helper="Compress old logs before deletion"
                                    checked={formData.logCleanup.compressOld}
                                    onChange={v => handleToggle('logCleanup.compressOld', v)}
                                />
                            </div>
                        </Section>
                    </div>
                </div>

                {/* ── Sticky Action Bar ─────────────────────────────── */}
                <div className="fixed bottom-8 left-1/2 -translate-x-1/2 flex items-center gap-4 px-6 py-4 bg-neutral-900/80 backdrop-blur-md rounded-full border border-neutral-700 shadow-2xl z-[100] animate-in slide-in-from-bottom-5">
                    <button
                        type="button"
                        onClick={() => setShowTutorial(true)}
                        className="px-6 py-2.5 rounded-full bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-sm font-bold transition-all"
                    >
                        Tutorial
                    </button>
                    <button
                        type="submit"
                        disabled={loading}
                        className="px-10 py-2.5 rounded-full bg-primary-600 hover:bg-primary-500 text-white text-sm font-bold transition-all flex items-center gap-2 shadow-lg shadow-primary-950/20"
                    >
                        {loading && <i className="bi bi-arrow-repeat animate-spin"></i>}
                        Save Config
                    </button>
                </div>
            </form>

            {/* ── Tutorial Modal ─────────────────────────────────── */}
            {showTutorial && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[1000] flex items-center justify-center p-6 animate-in fade-in">
                    <div className="bg-neutral-900 border border-neutral-800 rounded-3xl w-full max-w-2xl overflow-hidden shadow-2xl scale-in-95 animate-in">
                        <div className="px-8 py-6 border-b border-neutral-800 flex items-center justify-between">
                            <h3 className="text-xl font-bold text-white flex items-center gap-3">
                                <i className="bi bi-patch-question-fill text-blue-400"></i>
                                Smart Alerts Guide
                            </h3>
                            <button onClick={() => setShowTutorial(false)} className="w-8 h-8 rounded-full bg-neutral-800 hover:bg-neutral-700 text-neutral-400 flex items-center justify-center transition-colors">
                                <i className="bi bi-x-lg"></i>
                            </button>
                        </div>
                        <div className="p-8">
                            <div className="flex gap-2 mb-8 bg-neutral-950 p-1 rounded-2xl border border-neutral-800">
                                <button 
                                    onClick={() => setTutorialTab('discord')}
                                    className={`flex-1 py-3 rounded-xl text-xs font-bold transition-all uppercase tracking-widest ${tutorialTab === 'discord' ? 'bg-primary-500 text-white' : 'text-neutral-500 hover:text-neutral-300'}`}
                                >
                                    Discord
                                </button>
                                <button 
                                    onClick={() => setTutorialTab('telegram')}
                                    className={`flex-1 py-3 rounded-xl text-xs font-bold transition-all uppercase tracking-widest ${tutorialTab === 'telegram' ? 'bg-primary-500 text-white' : 'text-neutral-500 hover:text-neutral-300'}`}
                                >
                                    Telegram
                                </button>
                            </div>

                            <div className="space-y-6">
                                {tutorialTab === 'discord' ? (
                                    <>
                                        <div className="space-y-4">
                                            <h4 className="text-sm font-bold text-neutral-200">Webhook Setup</h4>
                                            <ol className="space-y-3 text-xs text-neutral-400 list-decimal ml-4">
                                                <li>Open Server Settings → Integrations → Webhooks</li>
                                                <li>Create <span className="text-primary-400 font-bold">New Webhook</span></li>
                                                <li>Copy Webhook URL and paste it in the field behind</li>
                                            </ol>
                                        </div>
                                    </>
                                ) : (
                                    <>
                                        <div className="space-y-4">
                                            <h4 className="text-sm font-bold text-neutral-200">Bot Creation</h4>
                                            <ol className="space-y-3 text-xs text-neutral-400 list-decimal ml-4">
                                                <li>Search for <span className="text-primary-400 font-bold">@BotFather</span> on Telegram</li>
                                                <li>Run <code className="text-blue-300">/newbot</code> and get your token</li>
                                                <li>Add the bot to your group and target the chat ID</li>
                                            </ol>
                                        </div>
                                    </>
                                )}
                            </div>
                        </div>
                        <div className="px-8 py-6 bg-neutral-950/50 border-t border-neutral-800 text-center">
                            <p className="text-[10px] text-neutral-600 font-bold uppercase tracking-widest">Always test a simple start/stop after saving.</p>
                        </div>
                    </div>
                </div>
            )}
        </ReactAppShell>
    );
}

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <BrowserRouter>
                <ServerSmartAlertsPage pageData={data} />
            </BrowserRouter>
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
