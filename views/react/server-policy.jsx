import React, { useState } from 'react';
import ReactAppShell from './components/ReactAppShell';

export default function ServerPolicyPage({ pageData = {} }) {
    const { 
        server = {}, 
        policyConfig = {}, 
        canQueueRestart = false, 
        playbooksFeatureEnabled = false
    } = pageData;

    const [loading, setLoading] = useState(false);
    const [status, setStatus] = useState({ 
        type: pageData.error ? 'error' : (pageData.success ? 'success' : 'idle'), 
        message: pageData.error || pageData.success || '' 
    });

    const [config, setConfig] = useState({
        enabled: !!policyConfig.enabled,
        editLock: {
            enabled: !!(policyConfig.editLock && policyConfig.editLock.enabled),
            bannerEnabled: !!(policyConfig.editLock && policyConfig.editLock.bannerEnabled),
            bannerText: (policyConfig.editLock && policyConfig.editLock.bannerText) || ''
        },
        readOnlyFiles: {
            enabled: !!(policyConfig.readOnlyFiles && policyConfig.readOnlyFiles.enabled),
            patterns: Array.isArray(policyConfig.readOnlyFiles?.patterns) ? policyConfig.readOnlyFiles.patterns.join('\n') : ''
        },
        userBanner: {
            enabled: !!(policyConfig.userBanner && policyConfig.userBanner.enabled),
            text: (policyConfig.userBanner && policyConfig.userBanner.text) || ''
        },
        restartOnCrash: !!policyConfig.restartOnCrash,
        anomalyAction: policyConfig.anomalyAction || 'none',
        anomalyCpuThreshold: policyConfig.anomalyCpuThreshold || 300,
        anomalyMemoryThreshold: policyConfig.anomalyMemoryThreshold || 300,
        anomalyDurationSamples: policyConfig.anomalyDurationSamples || 5,
        maxRemediationsPerHour: policyConfig.maxRemediationsPerHour || 3,
        playbooks: {
            enabled: !!(policyConfig.playbooks && policyConfig.playbooks.enabled),
            crashLoop: {
                enabled: !!(policyConfig.playbooks?.crashLoop?.enabled),
                crashCount: policyConfig.playbooks?.crashLoop?.crashCount || 3,
                windowMinutes: policyConfig.playbooks?.crashLoop?.windowMinutes || 10,
                action: policyConfig.playbooks?.crashLoop?.action || 'none'
            },
            oomRecovery: {
                enabled: !!(policyConfig.playbooks?.oomRecovery?.enabled),
                action: policyConfig.playbooks?.oomRecovery?.action || 'none'
            }
        }
    });

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setStatus({ type: 'idle', message: '' });

        try {
            // Flatten patterns
            const patterns = config.readOnlyFiles.patterns.split('\n').map(p => p.trim()).filter(p => p);
            
            const payload = {
                enabled: config.enabled ? '1' : '0',
                editLockEnabled: config.editLock.enabled ? '1' : '0',
                editLockBannerEnabled: config.editLock.bannerEnabled ? '1' : '0',
                editLockBannerText: config.editLock.bannerText,
                readOnlyFilesEnabled: config.readOnlyFiles.enabled ? '1' : '0',
                readOnlyFilePatterns: patterns.join('\n'),
                userBannerEnabled: config.userBanner.enabled ? '1' : '0',
                userBannerText: config.userBanner.text,
                restartOnCrash: config.restartOnCrash ? '1' : '0',
                anomalyAction: config.anomalyAction,
                anomalyCpuThreshold: config.anomalyCpuThreshold,
                anomalyMemoryThreshold: config.anomalyMemoryThreshold,
                anomalyDurationSamples: config.anomalyDurationSamples,
                maxRemediationsPerHour: config.maxRemediationsPerHour,
                playbooksEnabled: config.playbooks.enabled ? '1' : '0',
                playbookCrashLoopEnabled: config.playbooks.crashLoop.enabled ? '1' : '0',
                playbookCrashLoopCrashCount: config.playbooks.crashLoop.crashCount,
                playbookCrashLoopWindowMinutes: config.playbooks.crashLoop.windowMinutes,
                playbookCrashLoopAction: config.playbooks.crashLoop.action,
                playbookOomRecoveryEnabled: config.playbooks.oomRecovery.enabled ? '1' : '0',
                playbookOomRecoveryAction: config.playbooks.oomRecovery.action
            };

            const res = await fetch(`/server/${server.containerId}/policy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams(payload)
            });

            if (res.redirected) {
                window.location.href = res.url;
                return;
            }

            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Failed to save policy');
            setStatus({ type: 'success', message: 'Policy configuration updated.' });
            setLoading(false);
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
            setLoading(false);
        }
    };

    const handleQueuedRestart = async (action) => {
        setLoading(true);
        try {
            const res = await fetch(`/server/${server.containerId}/policy/queued-restart`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ action })
            });
            if (res.redirected) { window.location.href = res.url; return; }
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Failed to update queued restart');
            window.location.reload();
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
            setLoading(false);
        }
    };

    const Section = ({ title, children, icon }) => (
        <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 p-6 shadow-sm overflow-hidden">
            <h2 className="text-sm font-black text-neutral-500 uppercase tracking-widest mb-6 px-1 flex items-center gap-2">
                <i className={`bi ${icon} text-primary-400 opacity-70`}></i>
                {title}
            </h2>
            <div className="space-y-6">
                {children}
            </div>
        </div>
    );

    const Toggle = ({ label, helper, checked, onChange, disabled }) => (
        <div className="flex items-center justify-between p-4 rounded-xl bg-neutral-950/50 border border-neutral-800 hover:border-neutral-700 transition-all cursor-pointer group" onClick={() => !disabled && onChange(!checked)}>
            <div className="flex flex-col gap-1 pr-4">
                <span className="text-sm font-bold text-neutral-200 group-hover:text-primary-400 transition-colors">{label}</span>
                {helper && <span className="text-[10px] text-neutral-500 uppercase tracking-tight leading-relaxed">{helper}</span>}
            </div>
            <button
                type="button"
                className={`relative w-10 h-5 rounded-full transition-colors shrink-0 ${checked ? 'bg-primary-500' : 'bg-neutral-800'}`}
                disabled={disabled}
            >
                <div className={`absolute top-1 left-1 w-3 h-3 bg-white rounded-full transition-transform ${checked ? 'translate-x-5' : ''}`}></div>
            </button>
        </div>
    );

    return (
        <ReactAppShell pageData={pageData} subtitle="Policy Engine">
            <form onSubmit={handleSubmit} className="max-w-7xl mx-auto space-y-6 pb-20">
                {/* ── Status Messages ─────────────────────────────────── */}
                {status.message && (
                    <div className={`p-4 rounded-xl border flex items-center gap-3 animate-in fade-in slide-in-from-top-2 duration-300 shadow-xl ${
                        status.type === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-400' : 
                        status.type === 'success' ? 'bg-green-500/10 border-green-500/20 text-green-400' : 
                        'bg-blue-500/10 border-blue-500/20 text-blue-400'
                    }`}>
                        <i className={`bi ${status.type === 'error' ? 'bi-exclamation-triangle-fill' : status.type === 'success' ? 'bi-check-circle-fill' : 'bi-info-circle-fill'}`}></i>
                        <span className="text-sm font-medium">{status.message}</span>
                        <button onClick={() => setStatus({ type: 'idle', message: '' })} className="ml-auto opacity-50 hover:opacity-100 transition-opacity">
                            <i className="bi bi-x-lg"></i>
                        </button>
                    </div>
                )}

                <div className="grid lg:grid-cols-2 gap-6">
                    {/* ── General & Edit Lock ────────────────────────────── */}
                    <div className="space-y-6">
                        <Section title="General" icon="bi-gear-fill">
                            <Toggle 
                                label="Enable Policy Engine" 
                                helper="Global toggles in Admin Settings must also be enabled" 
                                checked={config.enabled} 
                                onChange={v => setConfig({...config, enabled: v})} 
                            />
                        </Section>

                        <Section title="Edit Lock" icon="bi-lock-fill">
                            <Toggle 
                                label="Universal Lockdown" 
                                helper="Blocks all write operations for non-admin users (SFTP, Startup, Files)" 
                                checked={config.editLock.enabled} 
                                onChange={v => setConfig({...config, editLock: {...config.editLock, enabled: v}})} 
                            />
                            <div className="space-y-4 pt-2 border-t border-neutral-800 opacity-80 group">
                                <Toggle 
                                    label="Security Banner" 
                                    helper="Display a descriptive warning to restricted users" 
                                    checked={config.editLock.bannerEnabled} 
                                    onChange={v => setConfig({...config, editLock: {...config.editLock, bannerEnabled: v}})} 
                                />
                                <div className="space-y-1 px-1">
                                    <label className="text-[10px] font-black text-neutral-500 uppercase tracking-widest">Banner Message</label>
                                    <input 
                                        type="text" 
                                        maxLength={240}
                                        value={config.editLock.bannerText}
                                        onChange={e => setConfig({...config, editLock: {...config.editLock, bannerText: e.target.value}})}
                                        className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2.5 text-sm text-neutral-300 focus:outline-none focus:border-primary-500/50"
                                        placeholder="This server is under high-security lockdown."
                                    />
                                </div>
                            </div>
                        </Section>

                        <Section title="Read-Only Files" icon="bi-file-earmark-lock-fill">
                            <Toggle 
                                label="Selective Path Protection" 
                                helper="Block modification of specific folders or files (Globs supported)" 
                                checked={config.readOnlyFiles.enabled} 
                                onChange={v => setConfig({...config, readOnlyFiles: {...config.readOnlyFiles, enabled: v}})} 
                            />
                            <div className="space-y-1.5 px-1">
                                <label className="text-[10px] font-black text-neutral-500 uppercase tracking-widest flex items-center justify-between">
                                    Path Patterns
                                    <span className="text-[9px] font-medium lowercase tracking-normal text-neutral-600 italic">one per line</span>
                                </label>
                                <textarea 
                                    rows={5}
                                    value={config.readOnlyFiles.patterns}
                                    onChange={e => setConfig({...config, readOnlyFiles: {...config.readOnlyFiles, patterns: e.target.value}})}
                                    className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-3 text-xs font-mono text-blue-300 focus:outline-none focus:border-primary-500/50 leading-relaxed"
                                    placeholder="/plugins/**&#10;/server.properties&#10;/mods/*.jar"
                                />
                            </div>
                        </Section>
                    </div>

                    {/* ── Monitoring & Playbooks ─────────────────────────── */}
                    <div className="space-y-6">
                        <Section title="Monitoring & Alerts" icon="bi-shield-check">
                            <Toggle 
                                label="Custom Site Banner" 
                                helper="Permanent banner visible on all server pages" 
                                checked={config.userBanner.enabled} 
                                onChange={v => setConfig({...config, userBanner: {...config.userBanner, enabled: v}})} 
                            />
                            <input 
                                type="text" 
                                maxLength={240}
                                value={config.userBanner.text}
                                onChange={e => setConfig({...config, userBanner: {...config.userBanner, text: e.target.value}})}
                                className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2.5 text-sm text-neutral-300 focus:outline-none focus:border-primary-500/50 mb-4"
                                placeholder="Maintenance tonight at 22:00..."
                            />
                            
                            <hr className="border-neutral-800" />
                            
                            <Toggle 
                                label="Crash Remediation" 
                                helper="Instant auto-start when a process failure is detected" 
                                checked={config.restartOnCrash} 
                                onChange={v => setConfig({...config, restartOnCrash: v})} 
                            />
                        </Section>

                        <Section title="Anomaly Remediation" icon="bi-activity">
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-neutral-500 uppercase tracking-widest px-1">Action</label>
                                    <select 
                                        value={config.anomalyAction}
                                        onChange={e => setConfig({...config, anomalyAction: e.target.value})}
                                        className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2.5 text-sm text-neutral-300 focus:outline-none focus:border-primary-500/50"
                                    >
                                        <option value="none">None</option>
                                        <option value="restart">Restart</option>
                                        <option value="stop">Stop</option>
                                    </select>
                                </div>
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-neutral-500 uppercase tracking-widest px-1">CPU Threshold (%)</label>
                                    <input 
                                        type="number" 
                                        value={config.anomalyCpuThreshold}
                                        onChange={e => setConfig({...config, anomalyCpuThreshold: parseInt(e.target.value)})}
                                        className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2.5 text-sm text-neutral-300"
                                    />
                                </div>
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-neutral-500 uppercase tracking-widest px-1">RAM Threshold (%)</label>
                                    <input 
                                        type="number" 
                                        value={config.anomalyMemoryThreshold}
                                        onChange={e => setConfig({...config, anomalyMemoryThreshold: parseInt(e.target.value)})}
                                        className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2.5 text-sm text-neutral-300"
                                    />
                                </div>
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-black text-neutral-500 uppercase tracking-widest px-1">Max Remed. / Hour</label>
                                    <input 
                                        type="number" 
                                        value={config.maxRemediationsPerHour}
                                        onChange={e => setConfig({...config, maxRemediationsPerHour: parseInt(e.target.value)})}
                                        className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2.5 text-sm text-neutral-300"
                                    />
                                </div>
                            </div>
                            <div className="text-[10px] text-neutral-600 px-1 font-medium leading-relaxed">
                                Remediation triggers when thresholds are exceeded for {config.anomalyDurationSamples} consecutive samples.
                            </div>
                        </Section>

                        {playbooksFeatureEnabled && (
                            <Section title="Automated Playbooks" icon="bi-lightning-charge-fill">
                                <Toggle 
                                    label="Enable Playbooks" 
                                    helper="Active automated scripts after specific events" 
                                    checked={config.playbooks.enabled} 
                                    onChange={v => setConfig({...config, playbooks: {...config.playbooks, enabled: v}})} 
                                />
                                
                                <div className="p-4 rounded-xl bg-neutral-950/30 border border-neutral-800 space-y-4">
                                    <div className="flex items-center gap-2 mb-1">
                                        <i className="bi bi-arrow-repeat text-blue-400"></i>
                                        <span className="text-xs font-bold text-neutral-300">Crash Loop Guard</span>
                                    </div>
                                    <div className="grid grid-cols-2 gap-3">
                                        <div className="space-y-1">
                                            <label className="text-[9px] font-black text-neutral-600 uppercase tracking-widest">Count</label>
                                            <input type="number" value={config.playbooks.crashLoop.crashCount} onChange={e => setConfig({...config, playbooks: {...config.playbooks, crashLoop: {...config.playbooks.crashLoop, crashCount: parseInt(e.target.value)}}})} className="w-full bg-neutral-900 border border-neutral-800 rounded-lg px-3 py-1.5 text-xs text-neutral-300" />
                                        </div>
                                        <div className="space-y-1">
                                            <label className="text-[9px] font-black text-neutral-600 uppercase tracking-widest">Window (min)</label>
                                            <input type="number" value={config.playbooks.crashLoop.windowMinutes} onChange={e => setConfig({...config, playbooks: {...config.playbooks, crashLoop: {...config.playbooks.crashLoop, windowMinutes: parseInt(e.target.value)}}})} className="w-full bg-neutral-900 border border-neutral-800 rounded-lg px-3 py-1.5 text-xs text-neutral-300" />
                                        </div>
                                    </div>
                                </div>

                                <div className="p-4 rounded-xl bg-neutral-950/30 border border-neutral-800">
                                    <div className="flex items-center gap-2 mb-3">
                                        <i className="bi bi-memory text-red-400"></i>
                                        <span className="text-xs font-bold text-neutral-300">OOM Auto-Recovery</span>
                                    </div>
                                    <select 
                                        value={config.playbooks.oomRecovery.action}
                                        onChange={e => setConfig({...config, playbooks: {...config.playbooks, oomRecovery: {...config.playbooks.oomRecovery, action: e.target.value}}})}
                                        className="w-full bg-neutral-900 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-neutral-300 focus:outline-none"
                                    >
                                        <option value="none">Disabled</option>
                                        <option value="start">Auto-Start</option>
                                        <option value="restart">Force Restart</option>
                                    </select>
                                </div>
                            </Section>
                        )}

                        {/* ── Queued Restart ─────────────────────────────────── */}
                        {canQueueRestart && (
                            <div className="bg-orange-500/10 rounded-2xl border border-orange-500/20 p-6 space-y-4">
                                <div>
                                    <h3 className="text-sm font-bold text-orange-400 flex items-center gap-2">
                                        <i className="bi bi-hourglass-split"></i>
                                        Queued Empty-Server Restart
                                    </h3>
                                    <p className="text-xs text-orange-300/60 mt-1 leading-relaxed">
                                        Panoul va monitoriza numărul de jucători și va restarta serverul automat în momentul în care acesta rămâne gol.
                                    </p>
                                </div>
                                {policyConfig.queuedRestart?.enabled && (
                                    <div className="px-3 py-2 rounded-lg bg-orange-500/10 border border-orange-500/20 text-[11px] font-bold text-orange-400 animate-pulse">
                                        <i className="bi bi-broadcast mr-1.5"></i>
                                        A restart is currently queued for this server.
                                    </div>
                                )}
                                <div className="flex gap-3">
                                    <button 
                                        type="button"
                                        onClick={() => handleQueuedRestart('queue')}
                                        disabled={loading}
                                        className="px-4 py-2 rounded-xl bg-orange-500 text-white text-xs font-bold hover:bg-orange-600 transition-colors shadow-lg shadow-orange-950/20"
                                    >
                                        Queue Restart
                                    </button>
                                    <button 
                                        type="button"
                                        onClick={() => handleQueuedRestart('cancel')}
                                        disabled={loading}
                                        className="px-4 py-2 rounded-xl bg-neutral-800 text-neutral-300 text-xs font-bold hover:bg-neutral-700 transition-colors"
                                    >
                                        Cancel Queue
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* ── Sticky Action Bar ─────────────────────────────── */}
                <div className="fixed bottom-8 left-1/2 -translate-x-1/2 flex items-center gap-4 px-6 py-4 bg-neutral-900/80 backdrop-blur-md rounded-full border border-neutral-700 shadow-2xl z-[100] animate-in slide-in-from-bottom-5">
                    <div className="flex flex-col pr-4 border-r border-neutral-800 leading-none">
                        <span className="text-[10px] font-black text-neutral-500 uppercase tracking-widest">Modified</span>
                        <span className="text-xs font-bold text-neutral-200">Policy Config</span>
                    </div>
                    <button
                        type="submit"
                        disabled={loading}
                        className="px-8 py-2.5 rounded-full bg-primary-600 hover:bg-primary-500 text-white text-sm font-bold transition-all flex items-center gap-2 shadow-lg shadow-primary-950/20"
                    >
                        {loading && <i className="bi bi-arrow-repeat animate-spin"></i>}
                        Save Policy Changes
                    </button>
                    <button
                        type="button"
                        onClick={() => window.location.reload()}
                        className="px-4 py-2.5 rounded-full bg-neutral-800 hover:bg-neutral-700 text-neutral-400 text-sm font-bold transition-all"
                    >
                        Discard
                    </button>
                </div>
            </form>
        </ReactAppShell>
    );
}
