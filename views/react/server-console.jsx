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

function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}

function appendSample(values, nextValue) {
    const safeValue = Number.isFinite(nextValue) ? nextValue : 0;
    const next = [...(Array.isArray(values) ? values : []), safeValue];
    return next.slice(-36);
}

function buildSparklinePath(values = []) {
    if (!Array.isArray(values) || values.length === 0) return '';
    const max = Math.max(...values, 1);
    const min = Math.min(...values, 0);
    const range = Math.max(1, max - min);
    return values
        .map((value, index) => {
            const x = values.length === 1 ? 100 : (index / (values.length - 1)) * 100;
            const y = 100 - (((value - min) / range) * 100);
            return `${x},${y}`;
        })
        .join(' ');
}

function usagePercent(value, limit) {
    const safeValue = parseMetric(value);
    const safeLimit = parseMetric(limit);
    if (!safeLimit) return 0;
    return clamp((safeValue / safeLimit) * 100, 0, 100);
}

function Sparkline({ values, tone }) {
    const points = buildSparklinePath(values);
    return (
        <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="react-console-sparkline">
            {points ? (
                <polyline
                    fill="none"
                    stroke={tone}
                    strokeWidth="4"
                    strokeLinejoin="round"
                    strokeLinecap="round"
                    points={points}
                />
            ) : (
                <line x1="0" y1="82" x2="100" y2="82" stroke="rgba(255,255,255,0.14)" strokeWidth="2" />
            )}
        </svg>
    );
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

function MetricChartCard({ title, value, note, values, tone }) {
    return (
        <section className="react-console-chart-card">
            <div className="react-console-chart-head">
                <div>
                    <h3>{title}</h3>
                    <div className="react-console-chart-note">{note}</div>
                </div>
                <div className="react-console-chart-value">{value}</div>
            </div>
            <Sparkline values={values} tone={tone} />
        </section>
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
        disk: parseMetric(pageData.initialStats && pageData.initialStats.disk)
    });
    const [samples, setSamples] = React.useState({
        cpu: [],
        memory: [],
        disk: []
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
                                break;
                            case 'connector_status':
                                setConnectorOnline(Boolean(payload.online));
                                break;
                            case 'server_stats': {
                                const nextCpu = parseMetric(payload.cpu);
                                const nextMemory = parseMetric(payload.memory);
                                const nextDisk = parseMetric(payload.disk);
                                setStats({ cpu: nextCpu, memory: nextMemory, disk: nextDisk });
                                setSamples((current) => ({
                                    cpu: appendSample(current.cpu, nextCpu),
                                    memory: appendSample(current.memory, nextMemory),
                                    disk: appendSample(current.disk, nextDisk)
                                }));
                                break;
                            }
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

    return (
        <ReactAppShell pageData={pageData} subtitle="React server console" pageClassName="react-console-page" shellClassName="react-console-shell">
            <div className="react-console-frame">
                <ServerSubnav items={pageData.serverNavItems} />
                <main className="react-console-layout">
                    <aside className="react-console-side">
                    <section className="react-console-side-card">
                        <div className="react-console-server-header">
                            <div className={`react-console-status-dot is-${statusTone(status)}`}></div>
                            <div>
                                <h1>{server.name || 'Server Console'}</h1>
                                <div className="react-console-server-meta">
                                    {server.address || 'No allocation address'}
                                </div>
                            </div>
                        </div>

                        <div className="react-console-side-list">
                            <ResourceBadge icon="bi-hdd-stack" label="Status" value={formatStatus(status)} />
                            <ResourceBadge icon="bi-cpu" label="CPU Limit" value={limits.cpu ? `${limits.cpu}%` : 'Unlimited'} />
                            <ResourceBadge icon="bi-memory" label="Memory Limit" value={limits.memory ? `${limits.memory} MB` : 'Unlimited'} />
                            <ResourceBadge icon="bi-device-hdd" label="Disk Limit" value={limits.disk ? `${limits.disk} MB` : 'Unlimited'} />
                        </div>

                        <div className={`react-console-connection is-${connectorOnline ? 'success' : 'danger'}`}>
                            <i className={`bi ${connectorOnline ? 'bi-broadcast-pin' : 'bi-wifi-off'}`}></i>
                            <span>{connectionState}</span>
                        </div>
                    </section>

                    <section className="react-console-side-card">
                        <div className="react-console-actions">
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
                        <div className="react-console-side-note">
                            React beta keeps the live terminal and power controls here. Advanced side tools still remain on the EJS console for now.
                        </div>
                        <div className="react-console-side-links">
                            <Link to={ReactRoutes.changeView} className="react-account-button is-ghost">Change View</Link>
                            <a href={`/server/${server.containerId}?popout=true`} className="react-account-button is-ghost">Popout</a>
                        </div>
                    </section>
                    </aside>

                    <section className="react-console-main">
                        {pageData.success ? <div className="react-account-flash is-success">{pageData.success}</div> : null}
                        {pageData.error ? <div className="react-account-flash is-danger">{pageData.error}</div> : null}
                        {terminalError ? <div className="react-account-flash is-danger">{terminalError}</div> : null}

                        <section className="react-console-terminal-card">
                            <div className="react-console-terminal-head">
                                <div>
                                    <h2>Live Console</h2>
                                    <div className="react-console-chart-note">
                                        {server.description || 'Live runtime output through the same websocket channel used by the EJS console.'}
                                    </div>
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
                            <div className={`react-console-terminal-body${terminalBooted ? '' : ' is-loading'}`} ref={terminalHostRef}>
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

                        <div className="react-console-chart-grid">
                            <MetricChartCard
                                title="Memory Usage"
                                value={`${Math.round(stats.memory)} MB`}
                                note={`${memoryPercent.toFixed(0)}% of limit`}
                                values={samples.memory}
                                tone="#29c5ce"
                            />
                            <MetricChartCard
                                title="CPU Usage"
                                value={`${stats.cpu.toFixed(1)}%`}
                                note={limits.cpu ? `${limits.cpu}% cap configured` : 'Unlimited CPU cap'}
                                values={samples.cpu}
                                tone="#5e9bff"
                            />
                            <MetricChartCard
                                title="Disk Usage"
                                value={`${Math.round(stats.disk)} MB`}
                                note={`${diskPercent.toFixed(0)}% of limit`}
                                values={samples.disk}
                                tone="#f6a545"
                            />
                        </div>
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
