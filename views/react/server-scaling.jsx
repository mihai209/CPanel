import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import ThemeProvider from './components/ThemeContext.jsx';
import ReactAppShell from './components/ReactAppShell';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-scaling';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

const DAY_LABELS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

export default function ServerScalingPage({ pageData = {} }) {
    const { 
        server = {}, 
        scalingConfig = {}, 
        inventoryEnabled = false, 
        ownerInventory = { ramMb: 0, cpuPercent: 0, diskMb: 0, swapMb: 0 },
        canManageScaling = false 
    } = pageData;

    const config = scalingConfig || { enabled: false, timezone: 'UTC', rules: [] };
    const rules = Array.isArray(config.rules) ? config.rules : [];

    const [loading, setLoading] = useState(false);
    const [status, setStatus] = useState({ 
        type: pageData.error ? 'error' : (pageData.success ? 'success' : 'idle'), 
        message: pageData.error || pageData.success || '' 
    });

    const [settings, setSettings] = useState({
        timezone: config.timezone || 'UTC',
        enabled: config.enabled
    });

    const [newRule, setNewRule] = useState({
        name: '',
        timezone: config.timezone || 'UTC',
        hour: 0,
        minute: 0,
        memory: '',
        cpu: '',
        disk: '',
        swapLimit: '',
        ioWeight: '',
        pidsLimit: '',
        oomScoreAdj: '',
        daysOfWeek: [0, 1, 2, 3, 4, 5, 6],
        enabled: true,
        oomKillDisable: false
    });

    const handleSaveSettings = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const res = await fetch(`/server/${server.containerId}/scaling/settings`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ timezone: settings.timezone, enabled: settings.enabled ? '1' : '0' })
            });
            if (res.redirected) { window.location.href = res.url; return; }
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Failed to save settings');
            window.location.reload();
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
            setLoading(false);
        }
    };

    const handleAddRule = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const payload = { ...newRule, daysOfWeek: JSON.stringify(newRule.daysOfWeek), enabled: newRule.enabled ? '1' : '0', oomKillDisable: newRule.oomKillDisable ? '1' : '0' };
            const res = await fetch(`/server/${server.containerId}/scaling/rules`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams(payload)
            });
            if (res.redirected) { window.location.href = res.url; return; }
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Failed to add rule');
            window.location.reload();
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
            setLoading(false);
        }
    };

    const handleDeleteRule = async (ruleId) => {
        if (!window.confirm('Delete this scaling rule?')) return;
        setLoading(true);
        try {
            const res = await fetch(`/server/${server.containerId}/scaling/rules/${ruleId}/delete`, {
                method: 'POST'
            });
            if (res.redirected) { window.location.href = res.url; return; }
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Failed to delete rule');
            window.location.reload();
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
            setLoading(false);
        }
    };

    const formatDays = (list) => {
        const values = Array.isArray(list) ? list.map(v => parseInt(v, 10)) : [];
        if (values.length === 7 || values.length === 0) return 'Every day';
        return values.sort((a, b) => a - b).map(idx => DAY_LABELS[idx]).join(', ');
    };

    const formatLimit = (value, suffix) => {
        const parsed = parseInt(value, 10);
        if (isNaN(parsed) || parsed <= 0) return '-';
        return `${parsed}${suffix || ''}`;
    };

    return (
        <ReactAppShell pageData={pageData} subtitle="Scheduled Scaling">
            <div className="max-w-7xl mx-auto space-y-6">
                {/* ── Status Messages ─────────────────────────────────── */}
                {status.message && (
                    <div className={`p-4 rounded-xl border flex items-center gap-3 ${
                        status.type === 'error' ? 'bg-red-500/10 border-red-500/20 text-red-400' : 
                        status.type === 'success' ? 'bg-green-500/10 border-green-500/20 text-green-400' : 
                        'bg-blue-500/10 border-blue-500/20 text-blue-400'
                    }`}>
                        <i className={`bi ${status.type === 'error' ? 'bi-exclamation-triangle-fill' : status.type === 'success' ? 'bi-check-circle-fill' : 'bi-info-circle-fill'}`}></i>
                        <span className="text-sm font-medium">{status.message}</span>
                    </div>
                )}

                {/* ── Inventory Budget ───────────────────────────────── */}
                {inventoryEnabled && (
                    <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 p-6 flex flex-wrap gap-6 items-center">
                        <div className="flex-1 min-w-[200px]">
                            <h2 className="text-lg font-bold text-white flex items-center gap-2">
                                <i className="bi bi-wallet2 text-primary-400"></i>
                                Inventory Budget
                            </h2>
                            <p className="text-xs text-neutral-500 mt-1">Scaling consumes inventory on increase and returns it on decrease.</p>
                        </div>
                        <div className="flex flex-wrap gap-4">
                            {[
                                { label: 'RAM', val: ownerInventory.ramMb, unit: 'MB' },
                                { label: 'CPU', val: ownerInventory.cpuPercent, unit: '%' },
                                { label: 'Disk', val: ownerInventory.diskMb, unit: 'MB' },
                                { label: 'Swap', val: ownerInventory.swapMb, unit: 'MB' }
                            ].map(item => (
                                <div key={item.label} className="px-4 py-2 rounded-xl bg-neutral-950/50 border border-neutral-800 text-center min-w-[100px]">
                                    <div className="text-[10px] font-black text-neutral-500 uppercase tracking-widest">{item.label}</div>
                                    <div className="text-sm font-bold text-neutral-200">{item.val} {item.unit}</div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                <div className="grid lg:grid-cols-12 gap-6">
                    {/* ── Left Column: Config & Form ──────────────────────── */}
                    <div className="lg:col-span-5 space-y-6">
                        {/* ── Engine Settings ─────────────────────────────── */}
                        <div className="bg-neutral-900/50 rounded-2xl border border-neutral-800 p-6 shadow-sm">
                            <h2 className="text-sm font-black text-neutral-500 uppercase tracking-widest mb-6 px-1">Engine Configuration</h2>
                            <form onSubmit={handleSaveSettings} className="space-y-4">
                                <div className="grid grid-cols-2 gap-4">
                                    <div className="space-y-2">
                                        <label className="text-[11px] font-bold text-neutral-400 px-1">System Timezone</label>
                                        <input
                                            value={settings.timezone}
                                            onChange={e => setSettings({...settings, timezone: e.target.value})}
                                            className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2.5 text-sm text-neutral-200 focus:outline-none focus:border-primary-500"
                                            placeholder="Europe/Bucharest"
                                        />
                                    </div>
                                    <div className="flex flex-col justify-center gap-1 mt-4">
                                        <div className="flex items-center justify-between p-2.5 rounded-xl bg-neutral-950 border border-neutral-800">
                                            <span className="text-[11px] font-bold text-neutral-300">Enabled</span>
                                            <button
                                                type="button"
                                                onClick={() => setSettings({...settings, enabled: !settings.enabled})}
                                                className={`relative w-8 h-4 rounded-full transition-colors ${settings.enabled ? 'bg-primary-500' : 'bg-neutral-700'}`}
                                            >
                                                <div className={`absolute top-0.5 left-0.5 w-3 h-3 bg-white rounded-full transition-transform ${settings.enabled ? 'translate-x-4' : ''}`}></div>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                <div className="text-[10px] text-neutral-500 leading-relaxed italic">
                                    Rules run each minute and apply when day/hour/minute match in the rule timezone.
                                </div>
                                <button
                                    type="submit"
                                    disabled={loading || !canManageScaling}
                                    className="w-full py-2.5 rounded-xl bg-neutral-800 hover:bg-neutral-700 text-white font-bold transition-all text-xs"
                                >
                                    Update Engine Settings
                                </button>
                            </form>
                        </div>

                        {/* ── Add Rule Form ───────────────────────────────── */}
                        {canManageScaling && (
                            <div className="bg-neutral-900/80 backdrop-blur-md rounded-2xl border border-neutral-800 p-6 shadow-xl">
                                <h2 className="text-sm font-black text-neutral-500 uppercase tracking-widest mb-6 px-1">Create New Rule</h2>
                                <form onSubmit={handleAddRule} className="space-y-5">
                                    <div className="space-y-4">
                                        <div className="space-y-2">
                                            <label className="text-[11px] font-bold text-neutral-400 px-1">Rule Name</label>
                                            <input
                                                required
                                                value={newRule.name}
                                                onChange={e => setNewRule({...newRule, name: e.target.value})}
                                                className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2.5 text-sm text-neutral-200 focus:outline-none focus:border-primary-500"
                                                placeholder="e.g., Night Mode"
                                            />
                                        </div>
                                        <div className="grid grid-cols-2 gap-4">
                                            <div className="space-y-2">
                                                <label className="text-[11px] font-bold text-neutral-400 px-1">Hour (0-23)</label>
                                                <input
                                                    type="number" min="0" max="23"
                                                    value={newRule.hour}
                                                    onChange={e => setNewRule({...newRule, hour: parseInt(e.target.value)})}
                                                    className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2.5 text-sm text-neutral-200 focus:outline-none focus:border-primary-500"
                                                />
                                            </div>
                                            <div className="space-y-2">
                                                <label className="text-[11px] font-bold text-neutral-400 px-1">Minute (0-59)</label>
                                                <input
                                                    type="number" min="0" max="59"
                                                    value={newRule.minute}
                                                    onChange={e => setNewRule({...newRule, minute: parseInt(e.target.value)})}
                                                    className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2.5 text-sm text-neutral-200 focus:outline-none focus:border-primary-500"
                                                />
                                            </div>
                                        </div>
                                    </div>

                                    {/* Limits */}
                                    <div className="grid grid-cols-2 gap-3">
                                        {[
                                            { label: 'RAM (MB)', key: 'memory' },
                                            { label: 'CPU (%)', key: 'cpu' },
                                            { label: 'Disk (MB)', key: 'disk' },
                                            { label: 'Swap (MB)', key: 'swapLimit' }
                                        ].map(field => (
                                            <div key={field.key} className="space-y-1.5">
                                                <label className="text-[10px] font-bold text-neutral-500 px-1">{field.label}</label>
                                                <input
                                                    type="number"
                                                    value={newRule[field.key]}
                                                    onChange={e => setNewRule({...newRule, [field.key]: e.target.value})}
                                                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-xs text-neutral-200 focus:outline-none focus:border-primary-500"
                                                    placeholder="Keep current"
                                                />
                                            </div>
                                        ))}
                                    </div>

                                    {/* Days */}
                                    <div className="space-y-3">
                                        <label className="text-[11px] font-bold text-neutral-400 px-1 block">Active Days</label>
                                        <div className="flex flex-wrap gap-1.5">
                                            {DAY_LABELS.map((day, idx) => {
                                                const isActive = newRule.daysOfWeek.includes(idx);
                                                return (
                                                    <button
                                                        key={day}
                                                        type="button"
                                                        onClick={() => {
                                                            const next = isActive ? newRule.daysOfWeek.filter(i => i !== idx) : [...newRule.daysOfWeek, idx];
                                                            setNewRule({...newRule, daysOfWeek: next});
                                                        }}
                                                        className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all border ${
                                                            isActive ? 'bg-primary-500/10 border-primary-500/50 text-primary-400' : 'bg-neutral-950 border-neutral-800 text-neutral-600'
                                                        }`}
                                                    >
                                                        {day}
                                                    </button>
                                                );
                                            })}
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-4 py-2 border-t border-neutral-800 pt-4">
                                        <div className="flex items-center gap-2 cursor-pointer" onClick={() => setNewRule({...newRule, enabled: !newRule.enabled})}>
                                            <div className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${newRule.enabled ? 'bg-primary-500 border-primary-500' : 'bg-neutral-950 border-neutral-700'}`}>
                                                {newRule.enabled && <i className="bi bi-check-lg text-white text-[10px]"></i>}
                                            </div>
                                            <span className="text-[11px] font-bold text-neutral-400">Rule Enabled</span>
                                        </div>
                                        <div className="flex items-center gap-2 cursor-pointer" onClick={() => setNewRule({...newRule, oomKillDisable: !newRule.oomKillDisable})}>
                                            <div className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${newRule.oomKillDisable ? 'bg-orange-500 border-orange-500' : 'bg-neutral-950 border-neutral-700'}`}>
                                                {newRule.oomKillDisable && <i className="bi bi-check-lg text-white text-[10px]"></i>}
                                            </div>
                                            <span className="text-[11px] font-bold text-neutral-400">Disable OOM Kill</span>
                                        </div>
                                    </div>

                                    <button
                                        type="submit"
                                        disabled={loading}
                                        className="w-full py-3.5 rounded-xl bg-primary-600 hover:bg-primary-500 text-white font-bold transition-all shadow-lg shadow-primary-900/20 text-sm"
                                    >
                                        Create Scaling Rule
                                    </button>
                                </form>
                            </div>
                        )}
                    </div>

                    {/* ── Right Column: Rules List ─────────────────────── */}
                    <div className="lg:col-span-7 space-y-6">
                        <div className="bg-neutral-900/50 backdrop-blur-sm rounded-2xl border border-neutral-800 p-6 shadow-sm overflow-hidden">
                            <div className="flex items-center justify-between mb-8 px-1">
                                <div>
                                    <h2 className="text-lg font-bold text-white flex items-center gap-2">
                                        <i className="bi bi-list-task text-primary-400"></i>
                                        Active Rules
                                    </h2>
                                    <p className="text-xs text-neutral-500 mt-1 uppercase tracking-wider font-semibold">
                                        Automated resource management
                                    </p>
                                </div>
                                <span className="px-3 py-1.5 rounded-full bg-neutral-800 text-[10px] font-black uppercase tracking-widest text-neutral-400">
                                    {rules.length} Rules
                                </span>
                            </div>

                            {rules.length === 0 ? (
                                <div className="text-center py-20 bg-neutral-950/30 rounded-2xl border border-dashed border-neutral-800">
                                    <i className="bi bi-calendar-x text-5xl text-neutral-700 mb-4 block"></i>
                                    <p className="text-neutral-500 text-sm font-medium">No scaling rules configured.</p>
                                    <p className="text-[10px] text-neutral-700 uppercase tracking-widest font-black mt-2">Start by adding your first peak-time rule</p>
                                </div>
                            ) : (
                                <div className="space-y-4">
                                    {rules.map((rule) => (
                                        <div key={rule.id} className="group relative bg-neutral-900/30 rounded-2xl border border-neutral-800 p-5 hover:bg-neutral-800/20 transition-all">
                                            <div className="flex flex-wrap items-start justify-between gap-4 mb-4">
                                                <div className="space-y-1">
                                                    <div className="flex items-center gap-3">
                                                        <h3 className="font-bold text-neutral-200">{rule.name}</h3>
                                                        <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-widest ${
                                                            rule.enabled === false ? 'bg-neutral-800 text-neutral-500' : 'bg-green-500/10 text-green-500'
                                                        }`}>
                                                            {rule.enabled === false ? 'Disabled' : 'Enabled'}
                                                        </span>
                                                        {rule.oomKillDisable && (
                                                            <span className="px-2 py-0.5 rounded bg-orange-500/10 text-orange-500 text-[9px] font-black uppercase tracking-widest">
                                                                No-OOM
                                                            </span>
                                                        )}
                                                    </div>
                                                    <div className="flex items-center gap-3">
                                                        <div className="flex items-center gap-1.5 text-[11px] text-neutral-500 font-bold">
                                                            <i className="bi bi-calendar2-week"></i>
                                                            {formatDays(rule.daysOfWeek)}
                                                        </div>
                                                        <div className="flex items-center gap-1.5 text-[11px] text-blue-400 font-bold">
                                                            <i className="bi bi-clock"></i>
                                                            {String(rule.hour || 0).padStart(2, '0')}:{String(rule.minute || 0).padStart(2, '0')}
                                                            <span className="text-[9px] text-neutral-600 ml-1 font-medium">{rule.timezone}</span>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    {canManageScaling && (
                                                        <button
                                                            onClick={() => handleDeleteRule(rule.id)}
                                                            className="p-2 rounded-xl bg-red-500/5 text-red-500/30 hover:bg-red-500 hover:text-white transition-all opacity-0 group-hover:opacity-100"
                                                            title="Delete Rule"
                                                        >
                                                            <i className="bi bi-trash-fill"></i>
                                                        </button>
                                                    )}
                                                </div>
                                            </div>

                                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 rounded-xl bg-neutral-950/40 border border-neutral-800/50">
                                                {[
                                                    { label: 'RAM', val: formatLimit(rule.memory, ' MB') },
                                                    { label: 'CPU', val: formatLimit(rule.cpu, '%') },
                                                    { label: 'Disk', val: formatLimit(rule.disk, ' MB') },
                                                    { label: 'Swap', val: formatLimit(rule.swapLimit, ' MB') }
                                                ].map(limit => (
                                                    <div key={limit.label}>
                                                        <div className="text-[9px] font-black text-neutral-600 uppercase tracking-widest mb-0.5">{limit.label}</div>
                                                        <div className="text-xs font-bold text-neutral-300">{limit.val}</div>
                                                    </div>
                                                ))}
                                            </div>

                                            <div className="mt-3 flex items-center justify-between">
                                                <div className="text-[10px] text-neutral-500 font-medium italic">
                                                    Last Applied: <span className="text-neutral-400 font-bold not-italic">{rule.lastAppliedSlot || '-'}</span>
                                                </div>
                                                <div className="text-[10px] text-neutral-700 font-black uppercase tracking-tighter">
                                                    ID: {rule.id}
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>

                        {/* ── Tutorial Info ──────────────────────────────── */}
                        <div className="bg-primary-500/5 rounded-2xl border border-primary-500/10 p-6">
                            <h3 className="text-sm font-bold text-primary-400 mb-4 flex items-center gap-2">
                                <i className="bi bi-lightbulb-fill"></i>
                                Scaling Best Practices
                            </h3>
                            <ul className="space-y-3">
                                {[
                                    { title: 'Peak Hours', desc: 'Create a rule starting at 18:00 to increase RAM/CPU during high traffic.' },
                                    { title: 'Night Mode', desc: 'Create a rule for 02:00 to scale down resources and conserve inventory budget.' },
                                    { title: 'Selective', desc: 'Leave fields empty to keep existing limits. For example, only scale RAM while keeping Disk identical.' }
                                ].map((item, i) => (
                                    <li key={i} className="flex gap-3">
                                        <span className="w-1 h-1 rounded-full bg-primary-500/50 mt-2 shrink-0"></span>
                                        <div className="text-xs">
                                            <span className="text-neutral-200 font-bold block">{item.title}</span>
                                            <span className="text-neutral-500 leading-relaxed">{item.desc}</span>
                                        </div>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </ReactAppShell>
    );
}

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <BrowserRouter>
                <ServerScalingPage pageData={data} />
            </BrowserRouter>
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
