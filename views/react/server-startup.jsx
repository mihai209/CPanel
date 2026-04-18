import React, { useState, useEffect, useCallback } from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';
import ThemeProvider from './components/ThemeContext.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-startup';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ServerStartupPage({ pageData = data }) {
    const server = pageData.server || {};
    const image = pageData.image || {};
    const resolvedStartup = pageData.resolvedStartup || '';
    const startupWriteLocked = Boolean(pageData.startupWriteLocked);
    const presets = pageData.startupPresets || [];
    const dockerChoices = pageData.dockerChoices || [];
    const variableDefinitions = pageData.variableDefinitions || [];
    const resolvedVariables = pageData.resolvedVariables || {};

    const [selectedPresetId, setSelectedPresetId] = useState(pageData.selectedStartupPresetId || 'custom');
    const [dockerTag, setDockerTag] = useState(pageData.selectedDockerImage || '');
    
    // Controlled variable overrides for client side previews/syncs (specifically VPS preset sync)
    const [dynamicVars, setDynamicVars] = useState(resolvedVariables);

    const handleVarChange = (key, val) => {
        setDynamicVars(prev => ({ ...prev, [key]: val }));
    };

    // Auto-sync VPS presets like the legacy code
    useEffect(() => {
        if (dynamicVars.VPS_PRESET && dynamicVars.VPS_PRESET.includes('|')) {
            const [distro, release] = dynamicVars.VPS_PRESET.split('|', 2);
            if (distro && release) {
                if (dynamicVars.VPS_DISTRO !== distro || dynamicVars.VPS_RELEASE !== release) {
                    setDynamicVars(prev => ({
                        ...prev,
                        VPS_DISTRO: distro,
                        VPS_RELEASE: release
                    }));
                }
            }
        }
    }, [dynamicVars.VPS_PRESET]);

    const handleReinstall = (e) => {
        e.preventDefault();
        if (startupWriteLocked) return;
        
        if (window.confirm("Reinstall Server?\n\nThis will rebuild the container and may overwrite runtime changes. Are you completely sure you want to reinstall?")) {
            const form = document.getElementById('startupForm');
            if (form) {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'action';
                input.value = 'reinstall';
                form.appendChild(input);
                form.submit();
            }
        }
    };

    // Paper java 1.8.9 warning condition
    const imageNameLower = String(image.name || '').toLowerCase();
    const mcVersionValue = dynamicVars['MINECRAFT_VERSION'] ? String(dynamicVars['MINECRAFT_VERSION']).trim() : '';
    const showPaperWarning = imageNameLower.includes('paper') && mcVersionValue === '1.8.9';

    return (
        <ReactAppShell pageData={pageData} subtitle="Startup">
            <PageContentBlock title="Startup configuration" description="Manage Docker image, environment variables, and startup command templates.">

                {pageData.success && (
                    <div className="bg-green-600/20 border-l-4 border-green-600 text-green-100 p-4 rounded-r-lg mb-6 shadow-sm">
                        {pageData.success}
                    </div>
                )}
                {pageData.error && (
                    <div className="bg-red-600/20 border-l-4 border-red-600 text-red-100 p-4 rounded-r-lg mb-6 shadow-sm">
                        {pageData.error}
                    </div>
                )}

                {startupWriteLocked && (
                    <div className="bg-red-900/20 border border-red-900/50 text-red-200 p-4 rounded-lg mb-6 shadow-sm">
                        <div className="font-bold mb-1"><i className="bi bi-lock-fill me-2"></i>Startup Locked</div>
                        <p className="text-sm opacity-90">Edits are locked for this server. Only admins can change runtime variables, startup commands, or reinstall right now.</p>
                    </div>
                )}

                <form id="startupForm" method="POST" action={`/server/${server.containerId}/startup`} data-turbo="false">
                    <fieldset disabled={startupWriteLocked} className="space-y-6">

                        {/* Startup Template Card */}
                        <div className="bg-neutral-900 border border-neutral-700 rounded-lg shadow-sm overflow-hidden">
                            <div className="bg-neutral-800/50 px-5 py-4 border-b border-neutral-700">
                                <h6 className="m-0 font-bold text-neutral-100">Startup Command</h6>
                            </div>
                            <div className="p-5">
                                <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">Startup Template</label>
                                <textarea 
                                    name="startupTemplate" 
                                    className="w-full bg-neutral-800/80 border border-neutral-700 rounded px-4 py-3 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 font-mono mb-2" 
                                    rows="3" 
                                    placeholder="Leave blank to use image default..."
                                    defaultValue={server.startup || image.startup}
                                ></textarea>
                                <div className="text-xs text-neutral-500 mb-5">Optional override. Clear the field to use the image default template.</div>

                                <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">Resolved Startup</label>
                                <textarea 
                                    className="w-full bg-neutral-900 border border-neutral-800 rounded px-4 py-3 text-sm text-neutral-500 font-mono opacity-80 cursor-not-allowed" 
                                    readOnly 
                                    value={resolvedStartup}
                                ></textarea>
                                <div className="text-xs text-neutral-600 mt-2">
                                    Resolved command is computed from the template + current variables.
                                </div>
                            </div>
                        </div>

                        {/* Image Settings */}
                        <div className="bg-neutral-900 border border-neutral-700 rounded-lg shadow-sm overflow-hidden">
                            <div className="bg-neutral-800/50 px-5 py-4 border-b border-neutral-700">
                                <h6 className="m-0 font-bold text-neutral-100">Docker Image</h6>
                            </div>
                            <div className="p-5">
                                <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">Startup Preset</label>
                                <select 
                                    name="startupPreset" 
                                    className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 mb-2"
                                    value={selectedPresetId}
                                    onChange={(e) => setSelectedPresetId(e.target.value)}
                                >
                                    <option value="custom">Custom (no preset)</option>
                                    {presets.map(p => (
                                        <option key={p.id} value={p.id}>{p.label}</option>
                                    ))}
                                </select>
                                <div className="text-xs text-neutral-500 mb-4">
                                    Presets auto-fill common variables (Paper, Purpur, Forge, Fabric) and pass the same validation rules as manual values.
                                </div>

                                {selectedPresetId && selectedPresetId !== 'custom' && (
                                    <div className="mb-4">
                                        {presets.filter(p => p.id === selectedPresetId).map(preset => (
                                            <div key={preset.id} className="bg-neutral-800/50 border border-neutral-700/50 rounded-lg p-4">
                                                <div className="text-xs font-bold text-primary-400 uppercase tracking-wider mb-1">{preset.label} Preview</div>
                                                <div className="text-sm text-neutral-400 mb-3">{preset.description}</div>
                                                <pre className="text-xs text-neutral-300 font-mono bg-neutral-900 p-3 rounded overflow-x-auto border border-neutral-800">
                                                    {JSON.stringify(preset.variables, null, 2)}
                                                </pre>
                                            </div>
                                        ))}
                                    </div>
                                )}

                                <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">Docker Tag</label>
                                <select 
                                    name="dockerImage" 
                                    className="w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500"
                                    value={dockerTag}
                                    onChange={(e) => setDockerTag(e.target.value)}
                                >
                                    {dockerChoices.length > 0 ? (
                                        dockerChoices.map(c => (
                                            <option key={c.tag} value={c.tag}>{c.label} - {c.tag}</option>
                                        ))
                                    ) : (
                                        <option value={dockerTag}>{dockerTag}</option>
                                    )}
                                </select>
                                <div className="text-xs text-neutral-500 mt-2">
                                    Changing image and startup command are applied after <strong>Save and Restart</strong> or reinstall.
                                </div>
                            </div>
                        </div>

                        {/* Variables List */}
                        <div className="bg-neutral-900 border border-neutral-700 rounded-lg shadow-sm overflow-hidden">
                            <div className="bg-neutral-800/50 px-5 py-4 border-b border-neutral-700">
                                <h6 className="m-0 font-bold text-neutral-100">Environment Variables</h6>
                            </div>
                            <div className="p-5">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    {variableDefinitions.length === 0 ? (
                                        <div className="col-span-1 md:col-span-2 text-sm text-neutral-500">No configurable startup variables for this image.</div>
                                    ) : (
                                        variableDefinitions.map(variable => {
                                            const key = variable.env_variable;
                                            const isViewable = variable.user_viewable == 1 || variable.user_viewable === true;
                                            const isEditable = variable.user_editable == 1 || variable.user_editable === true;
                                            
                                            if (!isViewable) return null;

                                            const label = (typeof variable.name === 'string' && variable.name.trim()) ? variable.name.trim() : key;
                                            const currentValue = dynamicVars[key] ?? variable.default_value ?? '';
                                            const selectOptions = Array.isArray(variable.options) ? variable.options : (Array.isArray(variable.select_options) ? variable.select_options : []);
                                            const isSelectField = String(variable.field_type || '').toLowerCase() === 'select' && selectOptions.length > 0;

                                            return (
                                                <div key={key} className="flex flex-col">
                                                    <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-1.5">{label}</label>
                                                    {isSelectField ? (
                                                        <select 
                                                            name={`variables[${key}]`}
                                                            className={`w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 ${!isEditable ? 'opacity-70' : ''}`}
                                                            disabled={!isEditable}
                                                            value={String(currentValue)}
                                                            onChange={(e) => handleVarChange(key, e.target.value)}
                                                        >
                                                            {selectOptions.map(opt => {
                                                                const optVal = typeof opt === 'object' && opt !== null ? (opt.value ?? '') : opt;
                                                                const optLabel = typeof opt === 'object' && opt !== null ? (opt.label ?? opt.value ?? '') : opt;
                                                                return <option key={optVal} value={String(optVal)}>{String(optLabel)}</option>;
                                                            })}
                                                        </select>
                                                    ) : (
                                                        <input 
                                                            type="text"
                                                            name={`variables[${key}]`}
                                                            className={`w-full bg-neutral-800 border border-neutral-700 rounded px-3 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500 ${!isEditable ? 'opacity-70 bg-neutral-800/50' : ''}`}
                                                            readOnly={!isEditable}
                                                            value={String(currentValue)}
                                                            onChange={(e) => handleVarChange(key, e.target.value)}
                                                        />
                                                    )}
                                                    {(variable.description || variable.rules) && (
                                                        <div className="text-xs text-neutral-500 mt-2">
                                                            {variable.description}
                                                            {variable.rules && <span className="block mt-1 font-mono text-neutral-600 bg-neutral-800 rounded px-1.5 py-0.5 inline-block w-max">Rules: {variable.rules}</span>}
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })
                                    )}
                                </div>
                            </div>
                        </div>

                        {showPaperWarning && (
                            <div className="bg-red-900/20 border border-red-900/50 text-red-200 p-4 rounded-lg shadow-sm">
                                <i className="bi bi-exclamation-triangle-fill me-2 text-red-500"></i>
                                Paper does not provide build <strong>1.8.9</strong>. The install script falls back to latest, which usually needs Java 17+. Use <strong>1.8.8</strong> or switch Docker image to Java 17+.
                            </div>
                        )}

                        <div className="bg-blue-500/10 border border-blue-500/20 p-4 rounded-lg text-sm text-blue-300">
                            <strong>Note:</strong> Save updates the database settings only. Use <strong>Save and Restart</strong> to redeploy the runtime container with the new startup/image settings. Reinstall is optional and only needed if the container is broken.
                        </div>

                        {/* Actions group */}
                        <div className="flex flex-wrap gap-4 mt-8 bg-neutral-900 border border-neutral-700 p-4 rounded-lg">
                            <button type="submit" name="action" value="save" className="bg-primary-600 hover:bg-primary-500 text-white font-bold px-6 py-2.5 rounded transition shadow-sm ml-auto order-1 md:order-3">
                                <i className="bi bi-save me-2"></i> Save Changes
                            </button>
                            <button type="submit" name="action" value="apply" className="bg-yellow-500 hover:bg-yellow-400 text-neutral-900 font-bold px-6 py-2.5 rounded transition shadow-sm order-2 md:order-2">
                                <i className="bi bi-arrow-repeat me-2"></i> Save and Restart
                            </button>
                            <button type="button" onClick={handleReinstall} className="bg-transparent border border-red-500/50 text-red-500 hover:bg-red-500/10 font-bold px-6 py-2.5 rounded transition mr-auto order-3 md:order-1">
                                <i className="bi bi-exclamation-triangle me-2"></i> Reinstall
                            </button>
                        </div>
                    </fieldset>
                </form>

            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerStartupPage;

if (root) {
    root.render(
        <ThemeProvider pageData={data}>
            <ServerStartupPage pageData={data} />
        </ThemeProvider>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}