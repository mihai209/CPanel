import React from 'react';
import { createRoot } from 'react-dom/client';
import { Link } from 'react-router-dom';
import { ReactRoutes } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-console';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

const XTERM_CSS_URL = 'https://cdn.jsdelivr.net/npm/xterm@5.2.1/css/xterm.css';
const XTERM_SCRIPT_URLS = [
    'https://cdn.jsdelivr.net/npm/xterm@5.2.1/lib/xterm.js',
    'https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.7.0/lib/xterm-addon-fit.js',
    'https://cdn.jsdelivr.net/npm/xterm-addon-web-links@0.8.0/lib/xterm-addon-web-links.js',
    'https://cdn.jsdelivr.net/npm/xterm-addon-unicode11@0.6.0/lib/xterm-addon-unicode11.js'
];

let xtermAssetsPromise = null;

function ensureStyle(href) {
    if (typeof document === 'undefined') return;
    if (document.querySelector(`link[data-react-asset="${href}"]`)) return;
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = href;
    link.setAttribute('data-react-asset', href);
    document.head.appendChild(link);
}

function loadScript(src) {
    return new Promise((resolve, reject) => {
        const existing = document.querySelector(`script[data-react-asset="${src}"]`);
        if (existing) {
            if (existing.getAttribute('data-loaded') === '1') {
                resolve();
                return;
            }
            existing.addEventListener('load', () => resolve(), { once: true });
            existing.addEventListener('error', () => reject(new Error(`Failed to load ${src}`)), { once: true });
            return;
        }

        const script = document.createElement('script');
        script.src = src;
        script.async = true;
        script.setAttribute('data-react-asset', src);
        script.addEventListener('load', () => {
            script.setAttribute('data-loaded', '1');
            resolve();
        }, { once: true });
        script.addEventListener('error', () => reject(new Error(`Failed to load ${src}`)), { once: true });
        document.body.appendChild(script);
    });
}

function ensureXtermAssets() {
    if (typeof window !== 'undefined' && window.Terminal && window.FitAddon && window.WebLinksAddon && window.Unicode11Addon) {
        return Promise.resolve();
    }
    if (xtermAssetsPromise) return xtermAssetsPromise;
    ensureStyle(XTERM_CSS_URL);
    xtermAssetsPromise = XTERM_SCRIPT_URLS.reduce(
        (chain, src) => chain.then(() => loadScript(src)),
        Promise.resolve()
    );
    return xtermAssetsPromise;
}

function normalizeStatus(status) {
    return String(status || 'unknown').trim().toLowerCase() || 'unknown';
}

function formatStatus(status) {
    const value = normalizeStatus(status).replace(/_/g, ' ');
    return value.charAt(0).toUpperCase() + value.slice(1);
}

function statusTone(status) {
    const value = normalizeStatus(status);
    if (value === 'running') return 'success';
    if (['installing', 'reinstalling', 'starting', 'stopping'].includes(value)) return 'warning';
    if (['stopped', 'offline', 'error'].includes(value)) return 'danger';
    return 'muted';
}

function getToneColorClass(tone) {
    switch (tone) {
        case 'success': return 'bg-green-500';
        case 'warning': return 'bg-yellow-500';
        case 'danger': return 'bg-red-500';
        default: return 'bg-neutral-500';
    }
}

function parseMetric(value) {
    const numeric = Number.parseFloat(String(value || '0').replace(/[^0-9.-]/g, ''));
    if (!Number.isFinite(numeric)) return 0;
    return Math.max(0, numeric);
}

function formatBytes(value) {
    const bytes = Math.max(0, Number.parseFloat(String(value || '0')) || 0);
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let current = bytes;
    let index = 0;
    while (current >= 1024 && index < units.length - 1) {
        current /= 1024;
        index += 1;
    }
    return `${current >= 100 || index === 0 ? current.toFixed(0) : current.toFixed(2)} ${units[index]}`;
}

function formatDuration(value) {
    const seconds = Math.max(0, Number.parseInt(String(value || '0'), 10) || 0);
    if (!seconds) return '0s';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    const parts = [];
    if (days) parts.push(`${days}d`);
    if (hours) parts.push(`${hours}h`);
    if (minutes) parts.push(`${minutes}m`);
    if (secs || parts.length === 0) parts.push(`${secs}s`);
    return parts.slice(0, 3).join(' ');
}

function formatRuntimeSource(source) {
    const value = String(source || 'system').trim().toLowerCase().replace(/_/g, ' ');
    return value ? value.charAt(0).toUpperCase() + value.slice(1) : 'System';
}

function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}

function usagePercent(value, limit) {
    const safeValue = parseMetric(value);
    const safeLimit = parseMetric(limit);
    if (!safeLimit) return 0;
    return clamp((safeValue / safeLimit) * 100, 0, 100);
}

function ResourceBadge({ icon, label, value }) {
    return (
        <div className="flex items-center gap-3">
            <i className={`bi ${icon} text-lg text-neutral-400`}></i>
            <div>
                <strong className="block text-sm font-bold text-neutral-200">{value}</strong>
                <span className="block text-xs text-neutral-500">{label}</span>
            </div>
        </div>
    );
}

function InlineMetric({ title, value, note, tone = '' }) {
    const toneTextClass = tone === 'success' ? 'text-green-400' :
                        tone === 'warning' ? 'text-yellow-400' :
                        tone === 'danger' ? 'text-red-400' : 'text-primary-400';
    return (
        <div className="flex flex-col mb-1 pb-2 border-b border-neutral-700/50 last:border-0 last:pb-0">
            <div className="flex justify-between items-center">
                <span className="text-xs font-bold text-neutral-400 uppercase tracking-wide">{title}</span>
                <strong className={`font-mono text-sm ${toneTextClass}`}>{value}</strong>
            </div>
            <small className="text-xs text-neutral-500 mt-1">{note}</small>
        </div>
    );
}

function scrubAnsi(text) {
    return String(text || '').replace(/\\x1b/g, '\x1b');
}

function buildWsUrl(wsToken, containerId) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}/ws/server/${encodeURIComponent(String(containerId || ''))}?token=${encodeURIComponent(String(wsToken || ''))}`;
}

export function ServerConsolePage({ pageData = data }) {
    const [isPopout, setIsPopout] = React.useState(false);
    
    React.useEffect(() => {
        if (typeof window !== 'undefined') {
            setIsPopout(new URLSearchParams(window.location.search).get('popout') === 'true');
        }
    }, []);

    const server = pageData.server || {};
    const limits = server.limits || {};
    const historyStorageKey = React.useMemo(
        () => `cpanel.react.console.history.${server.containerId || 'server'}`,
        [server.containerId]
    );

    const isMinecraft = Boolean(pageData.isMinecraftServer);
    const macros = Array.isArray(pageData.commandMacros) ? pageData.commandMacros : [];
    const mcPerms = pageData.minecraftActionPermissions || {};

    const terminalHostRef = React.useRef(null);
    const terminalInstanceRef = React.useRef(null);
    const fitAddonRef = React.useRef(null);
    const wsRef = React.useRef(null);
    const reconnectTimerRef = React.useRef(null);
    const heartbeatTimerRef = React.useRef(null);
    const disposedRef = React.useRef(false);
    const followOutputRef = React.useRef(true);
    const historyIndexRef = React.useRef(-1);

    const [status, setStatus] = React.useState(normalizeStatus(server.status));
    const [connectorOnline, setConnectorOnline] = React.useState(Boolean(pageData.connectorOnline));
    const [commandValue, setCommandValue] = React.useState('');
    const [history, setHistory] = React.useState(() => {
        try {
            const raw = localStorage.getItem(historyStorageKey) || '[]';
            const parsed = JSON.parse(raw);
            return Array.isArray(parsed) ? parsed.filter((entry) => typeof entry === 'string' && entry.trim()).slice(0, 32) : [];
        } catch {
            return [];
        }
    });
    const [stats, setStats] = React.useState({
        cpu: parseMetric(pageData.initialStats && pageData.initialStats.cpu),
        memory: parseMetric(pageData.initialStats && pageData.initialStats.memory),
        disk: parseMetric(pageData.initialStats && pageData.initialStats.disk),
        networkRx: parseMetric(pageData.initialStats && pageData.initialStats.network_rx),
        networkTx: parseMetric(pageData.initialStats && pageData.initialStats.network_tx),
        uptimeSeconds: parseMetric(pageData.initialStats && pageData.initialStats.uptime_seconds)
    });
    const [exitInfo, setExitInfo] = React.useState({
        exitCode: null,
        oomKilled: false
    });
    const [runtimeMeta, setRuntimeMeta] = React.useState(() => {
        const incoming = pageData.runtimeMeta || {};
        return {
            lastSource: incoming.lastSource || 'system',
            lastReason: incoming.lastReason || '',
            cooldownUntil: incoming.cooldownUntil || null,
            crashLoopCount: incoming.crashLoopCount || 0,
            history: Array.isArray(incoming.history) ? incoming.history.slice(0, 6) : []
        };
    });
    const [connectionState, setConnectionState] = React.useState('Connecting...');
    const [followOutput, setFollowOutput] = React.useState(true);
    const [terminalError, setTerminalError] = React.useState('');
    const [terminalBooted, setTerminalBooted] = React.useState(false);
    const [showShortcuts, setShowShortcuts] = React.useState(false);
    
    // Minecraft Player List Hook
    const [players, setPlayers] = React.useState([]);
    const [playersLoading, setPlayersLoading] = React.useState(isMinecraft);
    const [playersError, setPlayersError] = React.useState('');

    React.useEffect(() => {
        if (!isMinecraft) return;
        let active = true;
        
        async function fetchPlayers() {
            if (!active) return;
            try {
                const bedrockMode = pageData.minecraftBedrockMode ? '1' : '0';
                const response = await fetch(`/server/${server.containerId}/minecraft/configs/status?bedrock=${bedrockMode}`);
                const payload = await response.json();
                if (!response.ok || !payload.success) throw new Error(payload.error || 'Failed to sync players');
                if (active) {
                    setPlayers(payload.status?.playersList || []);
                    setPlayersError('');
                    setPlayersLoading(false);
                }
            } catch (err) {
                if (active) setPlayersError(err.message || 'Player sync failed');
            }
        }
        
        fetchPlayers();
        const interval = setInterval(fetchPlayers, 30000);
        
        return () => {
            active = false;
            clearInterval(interval);
        };
    }, [isMinecraft, server.containerId]);

    const handleMcAction = async (action, player) => {
        const requiresReason = ['kick', 'ban', 'tempban'].includes(action);
        const requiresDuration = action === 'tempban';
        const requiresDestination = action === 'teleport';

        const extra = {};
        if (requiresDestination) {
            const destination = window.prompt(`Teleport destination for ${player}:`, '');
            if (!destination) return;
            extra.destination = String(destination).trim().slice(0, 64);
        }

        if (requiresDuration) {
            const duration = window.prompt(`Tempban duration for ${player} (e.g. 1h):`, '');
            if (!duration) return;
            extra.duration = String(duration).trim().slice(0, 16);
        }

        if (requiresReason) {
            const reason = window.prompt(`Reason for ${action.toUpperCase()} ${player}:`, '');
            if (!reason) return;
            extra.reason = String(reason).trim().slice(0, 96);
        }

        const formData = new URLSearchParams();
        formData.append('action', action);
        formData.append('player', player);
        formData.append('bedrock', pageData.minecraftBedrockMode ? '1' : '0');
        if (extra.reason) formData.append('reason', extra.reason);
        if (extra.duration) formData.append('duration', extra.duration);
        if (extra.destination) formData.append('destination', extra.destination);

        try {
            await fetch(`/server/${server.containerId}/minecraft/configs`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData.toString()
            });
            // Let the regular loop grab the changes; maybe optimistically remove if kicked
        } catch (e) {
            console.error('Failed to dispatch action', e);
        }
    }


    React.useEffect(() => {
        followOutputRef.current = followOutput;
    }, [followOutput]);

    React.useEffect(() => {
        try {
            localStorage.setItem(historyStorageKey, JSON.stringify(history.slice(0, 32)));
        } catch {
            // Ignore storage failures in strict/private browsing mode.
        }
    }, [history, historyStorageKey]);

    React.useEffect(() => {
        disposedRef.current = false;
        setTerminalError('');
        setTerminalBooted(false);

        const stopHeartbeat = () => {
            if (heartbeatTimerRef.current) {
                clearInterval(heartbeatTimerRef.current);
                heartbeatTimerRef.current = null;
            }
        };

        const clearReconnect = () => {
            if (reconnectTimerRef.current) {
                clearTimeout(reconnectTimerRef.current);
                reconnectTimerRef.current = null;
            }
        };

        const teardownSocket = () => {
            stopHeartbeat();
            clearReconnect();
            if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
                wsRef.current.close(1000, 'Leaving React console');
            }
            wsRef.current = null;
        };

        const handleResize = () => {
            try {
                fitAddonRef.current && fitAddonRef.current.fit();
            } catch {
                // Ignore transient fit failures during resize.
            }
        };

        const boot = async () => {
            await ensureXtermAssets();
            if (disposedRef.current || !terminalHostRef.current) return;

            terminalHostRef.current.innerHTML = '';
            const term = new window.Terminal({
                theme: {
                    background: '#18181b', // neutral-900 equivalent for console
                    foreground: '#eef4fb',
                    cursor: '#eef4fb',
                    black: '#16161a',
                    red: '#ef4444',
                    green: '#10b981',
                    yellow: '#f59e0b',
                    blue: '#3b82f6',
                    magenta: '#8b5cf6',
                    cyan: '#06b6d4',
                    white: '#eef4fb'
                },
                allowProposedApi: true,
                fontFamily: 'Menlo, Monaco, "Courier New", monospace',
                fontSize: 13,
                cursorBlink: true,
                scrollback: 5000,
                convertEol: true,
                padding: '16px'
            });
            const fitAddon = new window.FitAddon.FitAddon();
            const webLinksAddon = new window.WebLinksAddon.WebLinksAddon();
            const unicode11Addon = new window.Unicode11Addon.Unicode11Addon();

            term.loadAddon(fitAddon);
            term.loadAddon(webLinksAddon);
            term.loadAddon(unicode11Addon);
            term.open(terminalHostRef.current);
            try {
                term.unicode.activeVersion = '11';
            } catch {
                // Unicode addon activation is optional.
            }
            fitAddon.fit();

            terminalInstanceRef.current = term;
            fitAddonRef.current = fitAddon;
            setTerminalBooted(true);

            if (pageData.initialConsoleBuffer) {
                term.write(scrubAnsi(pageData.initialConsoleBuffer));
                if (followOutputRef.current) {
                    term.scrollToBottom();
                }
            } else {
                term.writeln('\x1b[1;34m[*] React console ready.\x1b[0m');
            }

            let reconnectDelay = 1000;

            const connect = () => {
                if (disposedRef.current) return;
                setConnectionState('Connecting...');
                const ws = new WebSocket(buildWsUrl(pageData.wsToken, server.containerId));
                wsRef.current = ws;

                ws.onopen = () => {
                    reconnectDelay = 1000;
                    setConnectionState('Connected');
                    setConnectorOnline(true);
                    term.writeln('\x1b[1;32m[✓] Console stream connected.\x1b[0m');
                    stopHeartbeat();
                    heartbeatTimerRef.current = window.setInterval(() => {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ type: 'ping' }));
                        }
                    }, 30000);
                };

                ws.onmessage = (event) => {
                    try {
                        const payload = JSON.parse(event.data);
                        switch (payload.type) {
                            case 'console_output': {
                                const output = scrubAnsi(payload.output || '');
                                term.write(output);
                                if (followOutputRef.current) {
                                    term.scrollToBottom();
                                }
                                break;
                            }
                            case 'server_status_update':
                                setStatus(normalizeStatus(payload.status));
                                setExitInfo({
                                    exitCode: payload.exitCode !== undefined && payload.exitCode !== null && String(payload.exitCode).trim() !== ''
                                        ? String(payload.exitCode)
                                        : null,
                                    oomKilled: payload.oomKilled === true || String(payload.oomKilled || '').toLowerCase() === 'true'
                                });
                                break;
                            case 'connector_status':
                                setConnectorOnline(Boolean(payload.online));
                                break;
                            case 'server_stats': {
                                const nextCpu = parseMetric(payload.cpu);
                                const nextMemory = parseMetric(payload.memory);
                                const nextDisk = parseMetric(payload.disk);
                                const nextNetworkRx = parseMetric(payload.network_rx);
                                const nextNetworkTx = parseMetric(payload.network_tx);
                                const nextUptime = parseMetric(payload.uptime_seconds);
                                setStats({
                                    cpu: nextCpu,
                                    memory: nextMemory,
                                    disk: nextDisk,
                                    networkRx: nextNetworkRx,
                                    networkTx: nextNetworkTx,
                                    uptimeSeconds: nextUptime
                                });
                                break;
                            }
                            case 'server_runtime_meta':
                                setRuntimeMeta({
                                    lastSource: payload.lastSource || 'system',
                                    lastReason: payload.lastReason || '',
                                    cooldownUntil: payload.cooldownUntil || null,
                                    crashLoopCount: payload.crashLoopCount || 0,
                                    history: Array.isArray(payload.history) ? payload.history.slice(0, 6) : []
                                });
                                break;
                            case 'server_action_ack': {
                                const phase = String(payload.phase || '').toLowerCase();
                                const actionType = String(payload.actionType || 'action');
                                const text = String(payload.message || '').trim() || `${actionType} ${phase}`;
                                if (phase === 'failed') {
                                    term.writeln(`\x1b[1;31m[ACK] ${actionType}: ${text}\x1b[0m`);
                                } else if (phase === 'executed') {
                                    term.writeln(`\x1b[1;32m[ACK] ${actionType}: ${text}\x1b[0m`);
                                } else {
                                    term.writeln(`\x1b[1;34m[ACK] ${actionType}: ${text}\x1b[0m`);
                                }
                                break;
                            }
                            case 'error':
                                term.writeln(`\x1b[1;31m[!] ${String(payload.message || 'Unknown error')}\x1b[0m`);
                                break;
                            default:
                                break;
                        }
                    } catch (error) {
                        console.error('React console failed to parse websocket payload.', error);
                    }
                };

                ws.onclose = () => {
                    stopHeartbeat();
                    if (disposedRef.current) return;
                    setConnectionState('Disconnected');
                    setConnectorOnline(false);
                    term.writeln(`\x1b[1;33m[!] Connection lost. Reconnecting in ${Math.round(reconnectDelay / 1000)}s...\x1b[0m`);
                    clearReconnect();
                    reconnectTimerRef.current = window.setTimeout(() => {
                        reconnectDelay = Math.min(Math.round(reconnectDelay * 1.5), 5000);
                        connect();
                    }, reconnectDelay);
                };

                ws.onerror = (error) => {
                    console.error('React console websocket error:', error);
                    try {
                        ws.close();
                    } catch {
                        // Ignore close errors.
                    }
                };
            };

            connect();
            window.addEventListener('resize', handleResize);

            return () => {
                window.removeEventListener('resize', handleResize);
                teardownSocket();
                try {
                    term.dispose();
                } catch {
                    // Ignore dispose failures during route transitions.
                }
                terminalInstanceRef.current = null;
                fitAddonRef.current = null;
            };
        };

        let cleanup = null;
        boot()
            .then((nextCleanup) => {
                cleanup = nextCleanup;
            })
            .catch((error) => {
                console.error('React console bootstrap failed:', error);
                setTerminalError(error && error.message ? error.message : 'Failed to initialize terminal.');
            });

        return () => {
            disposedRef.current = true;
            if (typeof cleanup === 'function') cleanup();
            stopHeartbeat();
            clearReconnect();
            if (terminalInstanceRef.current) {
                try {
                    terminalInstanceRef.current.dispose();
                } catch {
                    // Ignore dispose failures during hard route transitions.
                }
                terminalInstanceRef.current = null;
            }
            fitAddonRef.current = null;
            wsRef.current = null;
        };
    }, [pageData.initialConsoleBuffer, pageData.wsToken, server.containerId]);

    const sendPayload = React.useCallback((payload) => {
        const socket = wsRef.current;
        if (!socket || socket.readyState !== WebSocket.OPEN) return false;
        socket.send(JSON.stringify(payload));
        return true;
    }, []);

    const recordHistory = React.useCallback((value) => {
        const trimmed = String(value || '').trim();
        if (!trimmed) return;
        setHistory((current) => [trimmed, ...current.filter((entry) => entry !== trimmed)].slice(0, 32));
        historyIndexRef.current = -1;
    }, []);

    const sendCommand = React.useCallback(() => {
        const command = String(commandValue || '').trim();
        if (!command) return;
        if (!sendPayload({ type: 'console_input', command })) return;
        recordHistory(command);
        setCommandValue('');
    }, [commandValue, recordHistory, sendPayload]);

    const runMacro = React.useCallback((macroId) => {
        if (!sendPayload({ type: 'run_macro', macroId })) return;
        const term = terminalInstanceRef.current;
        if (term) term.writeln(`\x1b[1;36m[*] Fired macro trigger...\x1b[0m`);
    }, [sendPayload]);

    const sendPowerAction = React.useCallback((action) => {
        if (!sendPayload({ type: 'power_action', action })) return;
        const term = terminalInstanceRef.current;
        if (term) {
            term.writeln(`\x1b[1;33m[*] Sending ${action} command...\x1b[0m`);
        }
    }, [sendPayload]);

    const isProvisioning = ['installing', 'reinstalling', 'starting'].includes(status);
    const isRestrictedProvisioningViewer = !pageData.user?.isAdmin && ['installing', 'reinstalling', 'starting'].includes(status);
    
    const startDisabled = !connectorOnline || isProvisioning || ['running', 'error'].includes(status);
    const restartDisabled = !connectorOnline || status !== 'running';
    const stopDisabled = !connectorOnline || status !== 'running';

    const memoryPercent = usagePercent(stats.memory, limits.memory);
    const diskPercent = usagePercent(stats.disk, limits.disk);
    const lastExitValue = exitInfo.exitCode ? `Exit code ${exitInfo.exitCode}` : 'No exit data';
    const lastExitNote = exitInfo.exitCode
        ? (exitInfo.oomKilled ? 'OOM kill detected for the last exit.' : 'Last stop did not carry an OOM kill flag.')
        : 'The runtime has not reported an exit event in this session.';
    const cooldownUntil = Number.parseInt(String(runtimeMeta.cooldownUntil || 0), 10) || 0;
    const cooldownActive = cooldownUntil > Date.now();
    const cooldownValue = cooldownActive ? 'Active' : 'Idle';
    const cooldownNote = cooldownActive
        ? `Cooldown until ${new Date(cooldownUntil).toLocaleString()}${runtimeMeta.crashLoopCount ? ` · loop count ${runtimeMeta.crashLoopCount}` : ''}`
        : (runtimeMeta.crashLoopCount ? `Crash loop count tracked: ${runtimeMeta.crashLoopCount}` : 'No crash cooldown is active.');

    const consoleShortcuts = [
        { action: 'Focus command input', keys: 'Ctrl + K' },
        { action: 'Send command', keys: 'Ctrl + Enter' },
        { action: 'Clear console output', keys: 'Ctrl + L' },
        { action: 'Search console', keys: 'Ctrl + F' },
        { action: 'Toggle auto-copy selection', keys: 'Ctrl + Shift + C' },
        { action: 'Browse command history', keys: 'Arrow Up / Arrow Down' },
        { action: 'Restart server', keys: 'Ctrl + Shift + R' },
        { action: 'Start/Stop server', keys: 'Ctrl + Shift + S' }
    ];

    const content = (
        <>
            {pageData.success && (
                <div className="bg-green-600/20 border border-green-600/50 text-green-100 p-4 rounded-lg mb-6 shadow-sm mx-4 lg:mx-8 mt-6">
                    {pageData.success}
                </div>
            )}
            {pageData.error && (
                <div className="bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm mx-4 lg:mx-8 mt-6">
                    {pageData.error}
                </div>
            )}
            {terminalError && (
                <div className="bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm mx-4 lg:mx-8 mt-6">
                    {terminalError}
                </div>
            )}

            <div className={`p-4 lg:p-8 grid grid-cols-1 ${isPopout ? '' : 'xl:grid-cols-4'} gap-6`}>
                
                {/* Main Console Surface */}
                <div className={isPopout ? '' : 'xl:col-span-3 flex flex-col gap-6 relative'}>
                    
                    {/* Header + Power Row */}
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                        <div className="flex items-center gap-4">
                            <div className={`w-3 h-3 rounded-full shrink-0 ${getToneColorClass(statusTone(status))}`}></div>
                            <div>
                                <h1 className="text-xl font-bold text-white tracking-wide">{server.name || 'Server Console'}</h1>
                                <p className="text-sm text-neutral-400 mt-1">{server.description || 'Live runtime output and power controls.'}</p>
                            </div>
                        </div>
                        
                        <div className="flex bg-neutral-800 rounded-lg border border-neutral-700/50 overflow-hidden shadow-sm shrink-0">
                            <button 
                                type="button" 
                                className="px-6 py-2.5 text-sm font-semibold hover:bg-neutral-700 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed border-r border-neutral-700/50 text-green-500" 
                                onClick={() => sendPowerAction('start')} 
                                disabled={startDisabled}
                            >
                                Start
                            </button>
                            <button 
                                type="button" 
                                className="px-6 py-2.5 text-sm font-semibold hover:bg-neutral-700 text-blue-400 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed border-r border-neutral-700/50" 
                                onClick={() => sendPowerAction('restart')} 
                                disabled={restartDisabled}
                            >
                                Restart
                            </button>
                            <button 
                                type="button" 
                                className="px-6 py-2.5 text-sm font-semibold hover:bg-neutral-700 text-red-500 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed" 
                                onClick={() => sendPowerAction('stop')} 
                                disabled={stopDisabled}
                            >
                                Stop
                            </button>
                            <button 
                                type="button" 
                                className={`px-6 py-2.5 text-sm font-semibold hover:bg-neutral-700 text-red-600 hover:text-red-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${status === 'stopping' ? '' : 'hidden'}`}
                                onClick={() => sendPowerAction('kill')} 
                            >
                                Kill
                            </button>
                        </div>
                    </div>
                    
                    {/* Quick Actions Bar */}
                    <div className="flex flex-wrap gap-2 items-center bg-neutral-900 border border-neutral-800 p-4 rounded-2xl shadow-inner shadow-black/40 mb-6">
                        <span className="text-[10px] font-black text-neutral-600 uppercase tracking-widest mr-2 flex items-center gap-1">
                            <i className="bi bi-lightning-fill text-yellow-500"></i> Actions
                        </span>
                        {macros.map(m => (
                            <button 
                                key={m.id}
                                onClick={() => runMacro(m.id)}
                                className="px-3 py-1.5 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 hover:border-neutral-500 rounded-xl text-[10px] font-black text-neutral-300 uppercase tracking-widest transition-all hover:scale-105 active:scale-95"
                            >
                                {m.name}
                            </button>
                        ))}
                        <div className="flex-1"></div>
                        <button 
                            onClick={() => setShowShortcuts(true)}
                            className="px-3 py-1.5 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 rounded-xl text-[10px] font-black text-neutral-400 hover:text-neutral-200 uppercase tracking-widest transition-all"
                        >
                            <i className="bi bi-keyboard me-2"></i> Shortcuts
                        </button>
                    </div>

                    {/* Terminal Block */}
                    <div className={`bg-neutral-900 border border-neutral-700 rounded-lg flex flex-col overflow-hidden shadow-lg relative ${isPopout ? 'h-[calc(100vh-280px)]' : 'h-[600px]'}`}>
                        
                        {/* Provisioning Overlay Map */}
                        {isProvisioning && (
                            <div className="absolute inset-0 bg-neutral-900/90 backdrop-blur-sm z-50 flex items-center justify-center p-6 text-center">
                                <div className="max-w-md w-full">
                                    <div className="w-12 h-12 rounded-full border-4 border-neutral-700 border-t-primary-500 animate-spin mb-6 mx-auto"></div>
                                    <h2 className="text-lg font-bold text-white mb-2 uppercase tracking-wide">
                                        Server Busy
                                    </h2>
                                    <p className="text-xs text-neutral-500 mb-6 font-bold uppercase tracking-widest">
                                        Current State: {status}
                                    </p>
                                    {isRestrictedProvisioningViewer ? (
                                        <div className="bg-red-500/10 border border-red-500/20 p-4 rounded-xl text-red-400 text-xs font-black uppercase tracking-widest leading-relaxed">
                                            <i className="bi bi-shield-lock me-2 text-sm"></i>
                                            Interaction is restricted during provisioning for security.
                                        </div>
                                    ) : (
                                        <div className="bg-neutral-800/50 p-4 rounded-xl text-neutral-400 text-xs font-bold uppercase tracking-widest italic">
                                            Admin access: Interaction enabled despite provisioning state.
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Terminal Header */}
                        <div className="bg-neutral-800 border-b border-neutral-700 px-4 py-3 flex justify-between items-center z-10 shrink-0">
                            <div className="flex items-center gap-3">
                                <span className="flex h-2 w-2 rounded-full bg-primary-500 shadow-[0_0_8px_rgba(59,130,246,0.6)]"></span>
                                <div>
                                    <strong className="text-neutral-100 font-bold block text-sm">Interactive Console</strong>
                                    <span className="text-[10px] text-neutral-500 font-black uppercase tracking-widest">Live Runtime Link</span>
                                </div>
                            </div>
                            <div className="flex bg-neutral-900 rounded-xl overflow-hidden border border-neutral-700 p-1 gap-1">
                                <button 
                                    className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${followOutput ? 'bg-primary-600 text-white shadow-lg' : 'text-neutral-500 hover:text-neutral-300 hover:bg-neutral-800'}`}
                                    onClick={() => setFollowOutput((current) => !current)}
                                >
                                    Follow
                                </button>
                                <button 
                                    className="px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest text-neutral-500 hover:text-neutral-300 hover:bg-neutral-800 transition-all"
                                    onClick={() => {
                                        const term = terminalInstanceRef.current;
                                        if (term) term.clear();
                                    }}
                                >
                                    Clear
                                </button>
                            </div>
                        </div>

                        {/* Terminal Canvas */}
                        <div className={`flex-1 relative ${terminalBooted ? '' : 'opacity-0'} p-2`} style={{ minHeight: 0 }}>
                            <div className="w-full h-full" ref={terminalHostRef}></div>
                        </div>
                        {!terminalBooted && !terminalError && !isProvisioning && (
                            <div className="absolute inset-x-0 bottom-16 top-16 flex items-center justify-center flex-col gap-4 text-neutral-500 bg-neutral-900/50 backdrop-blur-sm z-30">
                                <div className="w-8 h-8 border-4 border-neutral-700 border-t-primary-500 rounded-full animate-spin"></div>
                                <span className="text-[10px] font-black uppercase tracking-widest">Initializing Xterm...</span>
                            </div>
                        )}

                        {/* Input Row */}
                        <div className="bg-neutral-800 border-t border-neutral-700 flex flex-col md:flex-row items-center shrink-0">
                            <div className="flex-1 flex items-center w-full min-w-0">
                                <span className="text-neutral-500 pl-4 font-mono font-bold">$</span>
                                <input
                                    type="text"
                                    className="w-full bg-transparent border-none text-neutral-200 text-sm font-mono px-3 py-4 focus:ring-0 shadow-none outline-none disabled:opacity-50 disabled:cursor-not-allowed"
                                    value={commandValue}
                                    onChange={(event) => setCommandValue(event.target.value)}
                                    onKeyDown={(event) => {
                                        if (event.key === 'Enter') {
                                            event.preventDefault();
                                            sendCommand();
                                            return;
                                        }
                                        if (event.key === 'ArrowUp') {
                                            event.preventDefault();
                                            if (!history.length) return;
                                            historyIndexRef.current = Math.min(historyIndexRef.current + 1, history.length - 1);
                                            setCommandValue(history[historyIndexRef.current] || '');
                                            return;
                                        }
                                        if (event.key === 'ArrowDown') {
                                            event.preventDefault();
                                            if (!history.length) return;
                                            historyIndexRef.current = Math.max(historyIndexRef.current - 1, -1);
                                            setCommandValue(historyIndexRef.current >= 0 ? (history[historyIndexRef.current] || '') : '');
                                        }
                                    }}
                                    placeholder={isRestrictedProvisioningViewer ? 'Input locked during provisioning' : (connectorOnline ? 'Type a command and press Enter...' : 'Connector offline')}
                                    disabled={!connectorOnline || isRestrictedProvisioningViewer}
                                />
                            </div>
                            
                            {/* Actions Group */}
                            <div className="flex items-center w-full md:w-auto border-t md:border-t-0 md:border-l border-neutral-700 h-full">
                                <button 
                                    className="px-10 py-4 bg-primary-600 hover:bg-primary-500 font-black text-white text-[10px] uppercase tracking-[0.2em] transition-all disabled:opacity-50 disabled:cursor-not-allowed active:scale-95 flex items-center justify-center gap-2 h-full"
                                    onClick={sendCommand} 
                                    disabled={!connectorOnline || !String(commandValue || '').trim() || isRestrictedProvisioningViewer}
                                >
                                    Execute <i className="bi bi-terminal-fill"></i>
                                </button>
                            </div>
                        </div>
                    </div>

                    {showShortcuts && (
                        <div className="fixed inset-0 z-[100] flex items-center justify-center p-6">
                            <div className="absolute inset-0 bg-black/60 backdrop-blur-md" onClick={() => setShowShortcuts(false)}></div>
                            <div className="relative w-full max-w-lg bg-neutral-900 border border-neutral-800 rounded-[2.5rem] shadow-2xl overflow-hidden ring-1 ring-white/10">
                                <div className="p-8 border-b border-neutral-800 flex justify-between items-center">
                                    <div>
                                        <h2 className="text-xl font-bold text-white tracking-tight">Console Shortcuts</h2>
                                        <p className="text-xs text-neutral-500 font-bold uppercase tracking-widest mt-1">Boost your terminal workflow</p>
                                    </div>
                                    <button onClick={() => setShowShortcuts(false)} className="w-10 h-10 flex items-center justify-center rounded-xl bg-neutral-800 text-neutral-400 hover:text-white transition-colors">
                                        <i className="bi bi-x-lg"></i>
                                    </button>
                                </div>
                                <div className="p-8 space-y-4">
                                    {consoleShortcuts.map((sc, i) => (
                                        <div key={i} className="flex justify-between items-center group">
                                            <span className="text-sm font-bold text-neutral-400 group-hover:text-neutral-200 transition-colors">{sc.action}</span>
                                            <kbd className="px-3 py-1 bg-neutral-800 border border-neutral-700 rounded-lg text-[10px] font-black text-primary-400 font-mono scale-110 shadow-lg shadow-black/20">{sc.keys}</kbd>
                                        </div>
                                    ))}
                                </div>
                                <div className="p-8 bg-neutral-800/50 flex justify-center">
                                    <button 
                                        onClick={() => setShowShortcuts(false)}
                                        className="px-8 py-3 bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-700 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] transition-all"
                                    >
                                        Close Reference
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* Sidebar details */}
                {!isPopout && (
                    <aside className="xl:col-span-1 flex flex-col gap-4">
                        
                        {/* Connection Status Card */}
                        <div className="bg-neutral-800 border border-neutral-700 rounded-2xl p-5 shadow-lg">
                            <div className="text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 flex items-center gap-2">
                                <i className="bi bi-broadcast text-primary-400"></i> Connectivity
                            </div>
                            <div className="space-y-4">
                                <div className={`p-4 rounded-xl border flex flex-col gap-1 ${connectorOnline ? 'bg-green-500/5 border-green-500/10' : 'bg-red-500/5 border-red-500/10'}`}>
                                    <div className="flex items-center justify-between">
                                        <span className="text-[10px] font-bold text-neutral-500 uppercase tracking-wider">Daemon Status</span>
                                        <div className={`w-2 h-2 rounded-full ${connectorOnline ? 'bg-green-500 shadow-[0_0_10px_rgba(34,197,94,0.4)]' : 'bg-red-500'}`}></div>
                                    </div>
                                    <span className={`text-sm font-black uppercase tracking-widest ${connectorOnline ? 'text-green-400' : 'text-red-400'}`}>
                                        {connectionState}
                                    </span>
                                </div>
                                <div className="grid grid-cols-2 gap-2">
                                    <Link to={ReactRoutes.changeView} className="bg-neutral-900 border border-neutral-700 hover:border-neutral-500 text-neutral-300 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-xl text-center transition-all">
                                        View Mode
                                    </Link>
                                    <a href={`/server/${server.containerId}?popout=true`} target="_blank" rel="noopener noreferrer" className="bg-neutral-900 border border-neutral-700 hover:border-neutral-500 text-neutral-300 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-xl text-center transition-all">
                                        Popout
                                    </a>
                                </div>
                            </div>
                        </div>

                        {/* Minecraft Player View (if valid) */}
                        {isMinecraft && (
                            <div className="bg-neutral-800 border border-neutral-700 rounded-2xl p-5 shadow-lg flex flex-col max-h-[400px]">
                                <div className="flex justify-between items-center mb-4">
                                    <div className="text-[10px] font-black text-neutral-500 uppercase tracking-widest flex items-center gap-2">
                                        <i className="bi bi-people text-primary-400"></i> Players
                                    </div>
                                    <span className="text-[10px] font-black bg-neutral-900 border border-neutral-700 px-2 py-0.5 rounded-lg text-neutral-400">
                                        {players.length} Active
                                    </span>
                                </div>
                                <div className="flex-1 overflow-y-auto pr-1 custom-scrollbar">
                                    {playersLoading ? (
                                        <div className="text-[10px] font-black text-neutral-600 uppercase tracking-widest text-center py-8">Syncing...</div>
                                    ) : playersError ? (
                                        <div className="text-[10px] font-black text-red-500 uppercase tracking-widest text-center py-8">{playersError}</div>
                                    ) : players.length === 0 ? (
                                        <div className="text-[10px] font-black text-neutral-600 uppercase tracking-widest text-center py-8">Void Empty</div>
                                    ) : (
                                        <div className="flex flex-col gap-2">
                                            {players.map(p => (
                                                <div key={p.name} className="bg-neutral-900 border border-neutral-700/30 p-2 rounded-xl flex items-center justify-between group transition-colors hover:border-neutral-600">
                                                    <div className="flex items-center gap-2 min-w-0">
                                                        <img 
                                                            src={p.headUrl} 
                                                            className="w-6 h-6 rounded shadow-sm grayscale group-hover:grayscale-0 transition-all" 
                                                            alt={p.name} 
                                                            onError={(e) => { e.target.src = 'https://minotar.net/avatar/Steve/40' }}
                                                        />
                                                        <span className="text-xs font-bold text-neutral-300 truncate">{p.name}</span>
                                                    </div>
                                                    
                                                    <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                                        <button 
                                                            onClick={() => handleMcAction('kick', p.name)} 
                                                            disabled={!mcPerms.canKick}
                                                            className="w-6 h-6 flex items-center justify-center bg-neutral-800 hover:bg-red-900/40 text-neutral-400 hover:text-red-400 rounded-lg transition-colors"
                                                            title="Kick"
                                                        >
                                                            <i className="bi bi-door-open-fill text-[10px]"></i>
                                                        </button>
                                                        <button 
                                                            onClick={() => handleMcAction('ban', p.name)} 
                                                            disabled={!mcPerms.canBan}
                                                            className="w-6 h-6 flex items-center justify-center bg-neutral-800 hover:bg-red-900 text-neutral-400 hover:text-white rounded-lg transition-colors"
                                                            title="Ban"
                                                        >
                                                            <i className="bi bi-hammer text-[10px]"></i>
                                                        </button>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* System & Guards Card */}
                        <div className="bg-neutral-800 border border-neutral-700 rounded-2xl p-5 shadow-lg">
                            <div className="text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 flex items-center gap-2">
                                <i className="bi bi-cpu text-primary-400"></i> Vital Metrics
                            </div>
                            <div className="space-y-1">
                                <InlineMetric title="Core Load" value={`${stats.cpu.toFixed(1)}%`} note={limits.cpu ? `${limits.cpu}% cap` : 'No cap'} tone="primary" />
                                <InlineMetric title="Memory Buffer" value={`${Math.round(stats.memory)} MB`} note={`${memoryPercent.toFixed(0)}% used`} tone="success" />
                                <InlineMetric title="Disk Index" value={`${Math.round(stats.disk)} MB`} note={`${diskPercent.toFixed(0)}% used`} tone="warning" />
                                <InlineMetric title="Session Time" value={formatDuration(stats.uptimeSeconds)} note="Current runtime session" />
                                
                                <div className="h-px bg-neutral-700/50 my-4"></div>
                                
                                <div className="text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-4 flex items-center gap-2">
                                    <i className="bi bi-shield-check text-primary-400"></i> Guard System
                                </div>
                                <InlineMetric title="Last Trigger" value={formatRuntimeSource(runtimeMeta.lastSource)} note={runtimeMeta.lastReason || 'Stable state.'} />
                                <InlineMetric title="Cooldown" value={cooldownValue} note={cooldownNote} tone={cooldownActive ? 'warning' : 'primary'} />
                                <InlineMetric title="Exit Trace" value={lastExitValue} note={lastExitNote} tone={exitInfo.oomKilled ? 'danger' : 'primary'} />
                            </div>
                        </div>

                    </aside>
                )}
            </div>
        </>
    );

    if (isPopout) {
        return (
            <div className="min-h-screen bg-neutral-900 text-neutral-200">
                {content}
            </div>
        );
    }

    return (
        <ReactAppShell pageData={pageData} subtitle="React server console">
            {content}
        </ReactAppShell>
    );
}

export default ServerConsolePage;

if (root) {
    root.render(<ServerConsolePage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
