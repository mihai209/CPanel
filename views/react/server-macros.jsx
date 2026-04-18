import React, { useState } from 'react';
import ReactAppShell from './components/ReactAppShell';

export default function ServerMacrosPage({ pageData = {} }) {
    const { 
        server = {}, 
        macros: initialMacros = [], 
        canRunCommands = false, 
        canManageVisibility = false 
    } = pageData;

    const [macros, setMacros] = useState(initialMacros);
    const [loading, setLoading] = useState(false);
    const [status, setStatus] = useState({ 
        type: pageData.error ? 'error' : (pageData.success ? 'success' : 'idle'), 
        message: pageData.error || pageData.success || '' 
    });

    const handleAction = async (url, method = 'POST', body = null) => {
        setLoading(true);
        setStatus({ type: 'idle', message: '' });
        try {
            const options = { method };
            if (body) {
                options.headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
                options.body = new URLSearchParams(body);
            }

            const res = await fetch(url, options);
            if (res.redirected) {
                window.location.href = res.url;
                return;
            }

            const data = await res.json();
            if (!res.ok || data.error) throw new Error(data.error || 'Action failed');
            
            setStatus({ type: 'success', message: data.message || 'Action completed successfully.' });
            if (data.macros) setMacros(data.macros);
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
        } finally {
            setLoading(false);
        }
    };

    const MacroEditor = ({ macro = {}, isNew = false }) => {
        const [localMacro, setLocalMacro] = useState(isNew ? {
            name: '',
            description: '',
            visibility: 'all',
            runCondition: 'always',
            defaultDelayMs: 0,
            rollbackCommand: '',
            sequenceText: ''
        } : {
            ...macro,
            sequenceText: macro.sequenceText || macro.command || ''
        });

        const onSubmit = (e) => {
            e.preventDefault();
            const url = isNew 
                ? `/server/${server.containerId}/macros` 
                : `/server/${server.containerId}/macros/${macro.id}/update`;
            
            const body = {
                name: localMacro.name,
                description: localMacro.description,
                visibility: localMacro.visibility,
                runCondition: localMacro.runCondition,
                defaultDelayMs: localMacro.defaultDelayMs,
                rollbackCommand: localMacro.rollbackCommand,
                sequence: localMacro.sequenceText,
                position: localMacro.position || 0
            };
            handleAction(url, 'POST', body);
            if (isNew) {
                setLocalMacro({
                    name: '',
                    description: '',
                    visibility: 'all',
                    runCondition: 'always',
                    defaultDelayMs: 0,
                    rollbackCommand: '',
                    sequenceText: ''
                });
            }
        };

        return (
            <div className={`p-6 rounded-2xl border ${isNew ? 'bg-primary-500/5 border-primary-500/20' : 'bg-neutral-900/50 border-neutral-800'}`}>
                <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-3">
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${isNew ? 'bg-primary-500/20 text-primary-400' : 'bg-neutral-800 text-neutral-400'}`}>
                            <i className={`bi ${isNew ? 'bi-plus-circle-fill' : 'bi-terminal-fill'}`}></i>
                        </div>
                        <div>
                            <h3 className="text-sm font-black text-neutral-200 uppercase tracking-widest">{isNew ? 'Create New Macro' : localMacro.name}</h3>
                            {!isNew && <span className="text-[10px] text-neutral-500 font-bold uppercase tracking-tight">{macro.stepCount} steps • {macro.flowSummary}</span>}
                        </div>
                    </div>
                </div>

                <form onSubmit={onSubmit} className="space-y-4">
                    <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <div className="space-y-1.5">
                            <label className="text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1">Name</label>
                            <input 
                                value={localMacro.name} 
                                onChange={e => setLocalMacro({...localMacro, name: e.target.value})}
                                placeholder="Macro name" required maxLength={80}
                                className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2 text-xs text-neutral-300 focus:outline-none focus:border-primary-500/50"
                            />
                        </div>
                        <div className="space-y-1.5 lg:col-span-2">
                            <label className="text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1">Description</label>
                            <input 
                                value={localMacro.description} 
                                onChange={e => setLocalMacro({...localMacro, description: e.target.value})}
                                placeholder="Optional description" maxLength={160}
                                className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2 text-xs text-neutral-300 focus:outline-none focus:border-primary-500/50"
                            />
                        </div>
                        <div className="space-y-1.5">
                            <label className="text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1">Visibility</label>
                            <select 
                                value={localMacro.visibility} 
                                onChange={e => setLocalMacro({...localMacro, visibility: e.target.value})}
                                className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2 text-xs text-neutral-300 focus:outline-none focus:border-primary-500/50"
                            >
                                <option value="all">Public (All with macros)</option>
                                {canManageVisibility && <option value="owner">Owner Only</option>}
                                {canManageVisibility && <option value="admin">Admin Only</option>}
                                <option value="subuser">Subusers Only</option>
                            </select>
                        </div>
                    </div>

                    <div className="grid md:grid-cols-3 gap-4">
                        <div className="space-y-1.5">
                            <label className="text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1">Run Condition</label>
                            <select 
                                value={localMacro.runCondition} 
                                onChange={e => setLocalMacro({...localMacro, runCondition: e.target.value})}
                                className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2 text-xs text-neutral-300 focus:outline-none focus:border-primary-500/50"
                            >
                                <option value="always">Always Allow</option>
                                <option value="online">Only If Online</option>
                                <option value="offline">Only If Offline</option>
                            </select>
                        </div>
                        <div className="space-y-1.5">
                            <label className="text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1">Default Delay (ms)</label>
                            <input 
                                type="number" 
                                value={localMacro.defaultDelayMs} 
                                onChange={e => setLocalMacro({...localMacro, defaultDelayMs: e.target.value})}
                                placeholder="0" min="0" max="300000"
                                className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2 text-xs text-neutral-300 focus:outline-none focus:border-primary-500/50"
                            />
                        </div>
                        <div className="space-y-1.5">
                            <label className="text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1">Rollback Command</label>
                            <input 
                                value={localMacro.rollbackCommand} 
                                onChange={e => setLocalMacro({...localMacro, rollbackCommand: e.target.value})}
                                placeholder="Run if dispatch fails"
                                className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2 text-xs font-mono text-neutral-300 focus:outline-none focus:border-primary-500/50"
                            />
                        </div>
                    </div>

                    <div className="space-y-1.5">
                        <label className="text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1">Command Sequence</label>
                        <textarea 
                            value={localMacro.sequenceText} 
                            onChange={e => setLocalMacro({...localMacro, sequenceText: e.target.value})}
                            placeholder="say Starting update&#10;@delay 2000&#10;stop"
                            className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-3 text-xs font-mono text-neutral-300 focus:outline-none focus:border-primary-500/50 min-h-[120px] resize-y"
                        ></textarea>
                    </div>

                    <div className="flex items-center justify-between pt-2">
                        <div className="text-[10px] text-neutral-500 italic">
                            One command per line. Use @delay [ms] to wait.
                        </div>
                        <div className="flex gap-2">
                            {!isNew && (
                                <>
                                    <button 
                                        type="button"
                                        onClick={() => { if(confirm('Delete macro?')) handleAction(`/server/${server.containerId}/macros/${macro.id}/delete`, 'POST'); }}
                                        className="px-4 py-2 rounded-xl bg-red-500/10 hover:bg-red-500/20 text-red-400 text-xs font-black uppercase tracking-widest transition-all"
                                    >
                                        <i className="bi bi-trash"></i>
                                    </button>
                                    {canRunCommands && (
                                        <button 
                                            type="button"
                                            onClick={() => handleAction(`/server/${server.containerId}/macros/${macro.id}/run`, 'POST')}
                                            className="px-4 py-2 rounded-xl bg-green-500/10 hover:bg-green-500/20 text-green-400 text-xs font-black uppercase tracking-widest transition-all"
                                        >
                                            <i className="bi bi-play-fill"></i>
                                        </button>
                                    )}
                                </>
                            )}
                            <button 
                                type="submit" 
                                disabled={loading}
                                className={`px-6 py-2 rounded-xl text-white text-xs font-black uppercase tracking-widest transition-all ${isNew ? 'bg-primary-600 hover:bg-primary-500' : 'bg-neutral-800 hover:bg-neutral-700'}`}
                            >
                                {isNew ? 'Create Macro' : 'Save Changes'}
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        );
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Command Macros">
            <div className="max-w-5xl mx-auto space-y-8 pb-24">
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

                {/* ── Tutorial Info ─────────────────────────────────── */}
                <div className="bg-neutral-900/30 border border-neutral-800 rounded-2xl p-6 flex flex-wrap lg:flex-nowrap gap-6 items-start shadow-sm">
                    <div className="w-12 h-12 rounded-2xl bg-blue-500/10 flex items-center justify-center shrink-0 border border-blue-500/20">
                        <i className="bi bi-info-circle-fill text-blue-400 text-xl"></i>
                    </div>
                    <div className="space-y-4">
                        <div>
                            <h4 className="text-sm font-black text-neutral-200 uppercase tracking-widest mb-1">Advanced Macro Syntax</h4>
                            <p className="text-xs text-neutral-500 leading-relaxed m-0">Create complex workflows using logic gates and conditional steps.</p>
                        </div>
                        <div className="grid md:grid-cols-2 gap-x-8 gap-y-2">
                            <div className="flex items-center gap-2 text-[11px] text-neutral-400"><code className="bg-neutral-950 px-1.5 py-0.5 rounded text-primary-400 font-mono">@delay ms</code> <span>Waits specified time</span></div>
                            <div className="flex items-center gap-2 text-[11px] text-neutral-400"><code className="bg-neutral-950 px-1.5 py-0.5 rounded text-primary-400 font-mono">@onsuccess cmd</code> <span>Only if previous step worked</span></div>
                            <div className="flex items-center gap-2 text-[11px] text-neutral-400"><code className="bg-neutral-950 px-1.5 py-0.5 rounded text-primary-400 font-mono">@onfail cmd</code> <span>Only if previous step failed</span></div>
                            <div className="flex items-center gap-2 text-[11px] text-neutral-400"><code className="bg-neutral-950 px-1.5 py-0.5 rounded text-primary-400 font-mono">@if server_empty cmd</code> <span>0 players online requirement</span></div>
                        </div>
                    </div>
                </div>

                {/* ── New Macro ────────────────────────────────────── */}
                <MacroEditor isNew={true} />

                {/* ── List Macros ──────────────────────────────────── */}
                <div className="space-y-6">
                    <div className="flex items-center gap-3 px-1">
                        <i className="bi bi-stack text-neutral-600"></i>
                        <h3 className="text-[10px] font-black text-neutral-600 uppercase tracking-widest">Installed Macros</h3>
                    </div>

                    {macros.length === 0 ? (
                        <div className="bg-neutral-900/30 border border-neutral-800 rounded-2xl p-12 text-center">
                            <i className="bi bi-command text-4xl text-neutral-800 mb-4 block"></i>
                            <p className="text-sm text-neutral-500 italic m-0">No macros defined for this server yet.</p>
                        </div>
                    ) : (
                        <div className="space-y-4">
                            {macros.map(m => (
                                <MacroEditor key={m.id} macro={m} isNew={false} />
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </ReactAppShell>
    );
}
