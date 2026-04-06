import React from 'react';
import { createRoot } from 'react-dom/client';
import { Link } from 'react-router-dom';
import { ReactRoutes } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';

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

function ServerSubnav({ items }) {
    const navItems = Array.isArray(items) ? items.filter((item) => item && item.href && item.label) : [];
    if (!navItems.length) return null;
    return (
        <nav className="react-console-subnav">
            {navItems.map((item) => (
                item.active ? (
                    <span key={item.href} className="react-console-subnav-link is-active">{item.label}</span>
                ) : (
                    <a key={item.href} href={item.href} className="react-console-subnav-link">{item.label}</a>
                )
            ))}
        </nav>
    );
}

function ResourceBadge({ icon, label, value }) {
    return (
        <div className="react-console-resource">
            <i className={`bi ${icon}`}></i>
            <div>
                <strong>{value}</strong>
                <span>{label}</span>
            </div>
        </div>
    );
}

function InlineMetric({ title, value, note, tone = '' }) {
    return (
        <div className={`react-console-inline-metric${tone ? ` is-${tone}` : ''}`}>
            <span>{title}</span>
            <strong>{value}</strong>
            <small>{note}</small>
        </div>
    );
}

function buildTrendPoints(percent, seed) {
    const safe = clamp(Number(percent) || 0, 0, 100);
    const points = [];
    for (let index = 0; index < 12; index += 1) {
        const progress = index / 11;
        const wobble = Math.sin((index + seed) * 0.82) * 6 + Math.cos((index + seed) * 0.47) * 3;
        const value = clamp(safe * (0.38 + progress * 0.62) + wobble, 4, 100);
        const x = (index / 11) * 100;
        const y = 100 - value;
        points.push(`${x},${y}`);
    }
    return points.join(' ');
}

function MetricGraphCard({ title, value, note, percent, tone = 'info', seed = 1 }) {
    const safePercent = clamp(Number(percent) || 0, 0, 100);
    return (
        <article className={`react-console-graph-card is-${tone}`}>
            <div className="react-console-graph-head">
                <div>
                    <span>{title}</span>
                    <strong>{value}</strong>
                </div>
                <small>{note}</small>
            </div>
            <div className="react-console-graph-canvas">
                <svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
                    <defs>
                        <linearGradient id={`consoleGraphFill-${title.replace(/\s+/g, '-')}`} x1="0%" x2="0%" y1="0%" y2="100%">
                            <stop offset="0%" stopColor="currentColor" stopOpacity="0.34" />
                            <stop offset="100%" stopColor="currentColor" stopOpacity="0.02" />
                        </linearGradient>
                    </defs>
                    <polyline
                        className="react-console-graph-line"
                        points={buildTrendPoints(safePercent, seed)}
                        fill="none"
                        vectorEffect="non-scaling-stroke"
                    />
                    <polygon
                        className="react-console-graph-fill"
                        points={`0,100 ${buildTrendPoints(safePercent, seed)} 100,100`}
                        fill={`url(#consoleGraphFill-${title.replace(/\s+/g, '-')})`}
                    />
                </svg>
            </div>
        </article>
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
    const server = pageData.server || {};
    const limits = server.limits || {};
    const historyStorageKey = React.useMemo(
        () => `cpanel.react.console.history.${server.containerId || 'server'}`,
        [server.containerId]
    );

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
                    background: '#10161d',
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
                convertEol: true
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

    const sendPowerAction = React.useCallback((action) => {
        if (!sendPayload({ type: 'power_action', action })) return;
        const term = terminalInstanceRef.current;
        if (term) {
            term.writeln(`\x1b[1;33m[*] Sending ${action} command...\x1b[0m`);
        }
    }, [sendPayload]);

    const startDisabled = !connectorOnline || ['running', 'starting', 'stopping', 'installing', 'reinstalling', 'error'].includes(status);
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

    return (
        <ReactAppShell pageData={pageData} subtitle="React server console" pageClassName="react-console-page" shellClassName="react-console-shell">
            <div className="react-console-frame">
                <ServerSubnav items={pageData.serverNavItems} />
                <main className="react-console-board">
                    {pageData.success ? <div className="react-account-flash is-success">{pageData.success}</div> : null}
                    {pageData.error ? <div className="react-account-flash is-danger">{pageData.error}</div> : null}
                    {terminalError ? <div className="react-account-flash is-danger">{terminalError}</div> : null}

                    <section className="react-console-topbar">
                        <div className="react-console-titleblock">
                            <div className="react-console-titleline">
                                <div className={`react-console-status-dot is-${statusTone(status)}`}></div>
                                <h1>{server.name || 'Server Console'}</h1>
                            </div>
                            <p>{server.description || 'Live runtime output and power controls for this server.'}</p>
                        </div>

                        <div className="react-console-top-actions">
                            <button type="button" className="react-console-action is-success" onClick={() => sendPowerAction('start')} disabled={startDisabled}>
                                Start
                            </button>
                            <button type="button" className="react-console-action is-warning" onClick={() => sendPowerAction('restart')} disabled={restartDisabled}>
                                Restart
                            </button>
                            <button type="button" className="react-console-action is-danger" onClick={() => sendPowerAction('stop')} disabled={stopDisabled}>
                                Stop
                            </button>
                        </div>
                    </section>

                    <section className="react-console-core">
                        <section className="react-console-terminal-card">
                            <div className="react-console-terminal-head">
                                <div className="react-console-terminal-heading">
                                    <h2>Console</h2>
                                    <div className="react-console-chart-note">Interactive server stream with direct command input.</div>
                                </div>
                                <div className="react-console-terminal-tools">
                                    <button
                                        type="button"
                                        className={`react-console-mini-toggle${followOutput ? ' is-active' : ''}`}
                                        onClick={() => setFollowOutput((current) => !current)}
                                    >
                                        Follow
                                    </button>
                                    <button
                                        type="button"
                                        className="react-console-mini-toggle"
                                        onClick={() => {
                                            const term = terminalInstanceRef.current;
                                            if (term) {
                                                term.clear();
                                            }
                                        }}
                                    >
                                        Clear
                                    </button>
                                </div>
                            </div>
                            <div className={`react-console-terminal-body${terminalBooted ? '' : ' is-loading'}`}>
                                <div className="react-console-terminal-host" ref={terminalHostRef}></div>
                                {!terminalBooted && !terminalError ? (
                                    <div className="react-console-terminal-placeholder">Booting xterm runtime…</div>
                                ) : null}
                            </div>
                            <div className="react-console-command-row">
                                <span className="react-console-command-prefix">$</span>
                                <input
                                    type="text"
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
                                    className="react-console-command-input"
                                    placeholder={connectorOnline ? 'Type a command and press Enter…' : 'Connector offline'}
                                    disabled={!connectorOnline}
                                />
                                <button type="button" className="react-console-send" onClick={sendCommand} disabled={!connectorOnline || !String(commandValue || '').trim()}>
                                    Send
                                </button>
                            </div>
                        </section>

                        <aside className="react-console-details">
                            <section className="react-console-side-card">
                                <div className="react-console-panel-title">Server Details</div>
                                <div className="react-console-side-list">
                                    <ResourceBadge icon="bi-hdd-network" label="Allocation" value={server.address || 'No allocation address'} />
                                    <ResourceBadge icon="bi-hdd-stack" label="Status" value={formatStatus(status)} />
                                    <ResourceBadge icon="bi-cpu" label="CPU Cap" value={limits.cpu ? `${limits.cpu}%` : 'Unlimited'} />
                                    <ResourceBadge icon="bi-memory" label="RAM Cap" value={limits.memory ? `${limits.memory} MB` : 'Unlimited'} />
                                    <ResourceBadge icon="bi-device-hdd" label="Disk Cap" value={limits.disk ? `${limits.disk} MB` : 'Unlimited'} />
                                </div>
                            </section>

                            <section className="react-console-side-card">
                                <div className="react-console-panel-title">Connector Link</div>
                                <div className={`react-console-connection is-${connectorOnline ? 'success' : 'danger'}`}>
                                    <i className={`bi ${connectorOnline ? 'bi-broadcast-pin' : 'bi-wifi-off'}`}></i>
                                    <span>{connectionState}</span>
                                </div>
                                <div className="react-console-side-links">
                                    <Link to={ReactRoutes.changeView} className="react-account-button is-ghost">View Mode</Link>
                                    <a href={`/server/${server.containerId}?popout=true`} className="react-account-button is-ghost">Popout</a>
                                </div>
                            </section>

                            <section className="react-console-side-card">
                                <div className="react-console-panel-title">Runtime Snapshot</div>
                                <div className="react-console-side-list">
                                    <InlineMetric
                                        title="CPU"
                                        value={`${stats.cpu.toFixed(1)}%`}
                                        note={limits.cpu ? `${limits.cpu}% cap` : 'No cap'}
                                        tone="info"
                                    />
                                    <InlineMetric
                                        title="Memory"
                                        value={`${Math.round(stats.memory)} MB`}
                                        note={`${memoryPercent.toFixed(0)}% used`}
                                        tone="success"
                                    />
                                    <InlineMetric
                                        title="Disk"
                                        value={`${Math.round(stats.disk)} MB`}
                                        note={`${diskPercent.toFixed(0)}% used`}
                                        tone="warning"
                                    />
                                    <InlineMetric
                                        title="Uptime"
                                        value={formatDuration(stats.uptimeSeconds)}
                                        note="Current runtime session"
                                        tone="info"
                                    />
                                    <InlineMetric
                                        title="Net RX"
                                        value={formatBytes(stats.networkRx)}
                                        note="Inbound since start"
                                        tone="success"
                                    />
                                    <InlineMetric
                                        title="Net TX"
                                        value={formatBytes(stats.networkTx)}
                                        note="Outbound since start"
                                        tone="warning"
                                    />
                                </div>
                            </section>

                            <section className="react-console-side-card">
                                <div className="react-console-panel-title">Restart Source</div>
                                <div className="react-console-side-list">
                                    <InlineMetric
                                        title="Last Trigger"
                                        value={formatRuntimeSource(runtimeMeta.lastSource)}
                                        note={runtimeMeta.lastReason || 'No restart source captured yet.'}
                                        tone="info"
                                    />
                                </div>
                            </section>

                            <section className="react-console-side-card">
                                <div className="react-console-panel-title">Crash Cooldown</div>
                                <div className="react-console-side-list">
                                    <InlineMetric
                                        title="Guard State"
                                        value={cooldownValue}
                                        note={cooldownNote}
                                        tone={cooldownActive ? 'warning' : 'info'}
                                    />
                                </div>
                            </section>

                            <section className="react-console-side-card">
                                <div className="react-console-panel-title">Last Exit</div>
                                <div className="react-console-side-list">
                                    <InlineMetric
                                        title="Exit Summary"
                                        value={lastExitValue}
                                        note={lastExitNote}
                                        tone={exitInfo.oomKilled ? 'danger' : 'info'}
                                    />
                                </div>
                            </section>

                            <section className="react-console-side-card">
                                <div className="react-console-panel-title">Recent Runtime Events</div>
                                <div className="react-console-side-list">
                                    {Array.isArray(runtimeMeta.history) && runtimeMeta.history.length ? runtimeMeta.history.map((entry, index) => (
                                        <InlineMetric
                                            key={`${entry.kind || 'runtime'}-${entry.ts || index}-${index}`}
                                            title={`${entry.kind || 'runtime'} · ${formatRuntimeSource(entry.source)}`}
                                            value={entry.summary || 'Runtime event recorded.'}
                                            note={entry.ts ? new Date(entry.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Live'}
                                            tone={entry.tone || 'info'}
                                        />
                                    )) : (
                                        <InlineMetric
                                            title="Runtime"
                                            value="No recent events"
                                            note="Recent restart reasons and crash transitions will appear here."
                                            tone="info"
                                        />
                                    )}
                                </div>
                            </section>
                        </aside>
                    </section>

                    <section className="react-console-graphs">
                        <MetricGraphCard
                            title="CPU Usage"
                            value={`${stats.cpu.toFixed(1)}%`}
                            note={limits.cpu ? `${limits.cpu}% server limit` : 'No limit configured'}
                            percent={limits.cpu ? usagePercent(stats.cpu, limits.cpu) : clamp(stats.cpu, 0, 100)}
                            tone="info"
                            seed={1}
                        />
                        <MetricGraphCard
                            title="Memory Usage"
                            value={`${Math.round(stats.memory)} MB`}
                            note={limits.memory ? `${Math.round(limits.memory)} MB limit` : 'No memory limit'}
                            percent={memoryPercent}
                            tone="success"
                            seed={5}
                        />
                        <MetricGraphCard
                            title="Disk Usage"
                            value={`${Math.round(stats.disk)} MB`}
                            note={limits.disk ? `${Math.round(limits.disk)} MB limit` : 'No disk limit'}
                            percent={diskPercent}
                            tone="warning"
                            seed={9}
                        />
                    </section>
                </main>
            </div>
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
