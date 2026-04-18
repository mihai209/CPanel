import React, { useState, useEffect, useCallback, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-files';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

// ─── Utilities ────────────────────────────────────────────────────
function normalizePath(v) {
    const r = String(v || '/').trim().replace(/\\/g, '/');
    if (!r || r === '/') return '/';
    const n = r.startsWith('/') ? r : `/${r}`;
    return n.replace(/\/+/g, '/').replace(/\/$/, '') || '/';
}
function formatBytes(v) {
    const b = Math.max(0, Number(v) || 0);
    if (!b) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let c = b, i = 0;
    while (c >= 1024 && i < u.length - 1) { c /= 1024; i++; }
    return `${c >= 100 || i === 0 ? c.toFixed(0) : c.toFixed(2)} ${u[i]}`;
}
function formatDate(v) {
    if (!v) return '—';
    const d = new Date(v);
    return isNaN(d) ? '—' : d.toLocaleString();
}
function buildBreadcrumbs(path) {
    const n = normalizePath(path);
    if (n === '/') return [{ label: '', path: '/', icon: true }];
    const parts = n.split('/').filter(Boolean);
    const segs = [{ label: '', path: '/', icon: true }];
    let cur = '';
    parts.forEach(p => { cur += `/${p}`; segs.push({ label: p, path: cur }); });
    return segs;
}
function getFileIcon(entry) {
    if (entry.isDirectory) return 'bi-folder-fill text-amber-400';
    const ext = (entry.name || '').split('.').pop().toLowerCase();
    const map = {
        js: 'bi-filetype-js text-yellow-400', ts: 'bi-filetype-ts text-blue-400',
        json: 'bi-filetype-json text-green-400', yml: 'bi-filetype-yml text-orange-400',
        yaml: 'bi-filetype-yml text-orange-400', xml: 'bi-filetype-xml text-orange-300',
        html: 'bi-filetype-html text-orange-500', css: 'bi-filetype-css text-blue-500',
        py: 'bi-filetype-py text-green-500', php: 'bi-filetype-php text-purple-400',
        sh: 'bi-terminal text-green-300', md: 'bi-filetype-md text-neutral-300',
        txt: 'bi-file-earmark-text text-neutral-400',
        zip: 'bi-file-zip text-yellow-500', tar: 'bi-file-zip text-yellow-500',
        gz: 'bi-file-zip text-yellow-500', jar: 'bi-file-zip-fill text-red-400',
        png: 'bi-file-earmark-image text-pink-400', jpg: 'bi-file-earmark-image text-pink-400',
        jpeg: 'bi-file-earmark-image text-pink-400', gif: 'bi-file-earmark-image text-pink-400',
        mp4: 'bi-file-earmark-play text-red-400', mp3: 'bi-file-earmark-music text-purple-400',
        db: 'bi-database text-blue-300', sqlite: 'bi-database text-blue-300',
        sql: 'bi-database-fill text-blue-300', log: 'bi-file-earmark-text text-neutral-400',
        conf: 'bi-gear text-neutral-400', cfg: 'bi-gear text-neutral-400',
        ini: 'bi-gear text-neutral-400', properties: 'bi-gear text-neutral-400',
    };
    return map[ext] || 'bi-file-earmark text-neutral-500';
}
const ARCHIVE_EXTS = ['.zip', '.tar', '.tar.gz', '.tgz', '.gz', '.rar', '.7z'];
function isArchive(name) { return ARCHIVE_EXTS.some(e => name.toLowerCase().endsWith(e)); }
const MEDIA_IMAGE_EXTS = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp'];
const MEDIA_VIDEO_EXTS = ['.mp4', '.webm', '.mov', '.ogg'];
function mediaKind(name) {
    const n = name.toLowerCase();
    if (MEDIA_IMAGE_EXTS.some(e => n.endsWith(e))) return 'image';
    if (MEDIA_VIDEO_EXTS.some(e => n.endsWith(e))) return 'video';
    return null;
}

// ─── Generic Modal Shell ───────────────────────────────────────────
function Modal({ isOpen, onClose, title, children, maxW = 'max-w-md' }) {
    useEffect(() => {
        if (!isOpen) return;
        const handle = (e) => { if (e.key === 'Escape') onClose(); };
        window.addEventListener('keydown', handle);
        return () => window.removeEventListener('keydown', handle);
    }, [isOpen, onClose]);
    if (!isOpen) return null;
    return (
        <div className="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
            <div className={`bg-[#0f1115] border border-neutral-800 rounded-2xl w-full ${maxW} shadow-2xl overflow-hidden`}>
                <div className="px-6 py-4 border-b border-neutral-800 flex justify-between items-center">
                    <h3 className="text-base font-bold text-white">{title}</h3>
                    <button onClick={onClose} className="w-7 h-7 rounded flex items-center justify-center text-neutral-500 hover:text-white hover:bg-neutral-800 transition-colors"><i className="bi bi-x-lg text-sm"></i></button>
                </div>
                <div className="p-6">{children}</div>
            </div>
        </div>
    );
}

// ─── Search Modal ─────────────────────────────────────────────────
function SearchModal({ isOpen, onClose, serverId, onNavigate }) {
    const [query, setQuery] = useState('');
    const [filter, setFilter] = useState('all');
    const [results, setResults] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const abortRef = useRef(null);

    const doSearch = useCallback(async () => {
        if (!query.trim()) return;
        if (abortRef.current) abortRef.current.abort();
        const ctrl = new AbortController();
        abortRef.current = ctrl;
        setLoading(true); setError(''); setResults(null);
        try {
            const params = new URLSearchParams({ query: query.trim(), filter });
            const res = await fetch(`/server/${serverId}/files-search?${params}`, { signal: ctrl.signal });
            const payload = await res.json();
            if (!res.ok || payload.error) throw new Error(payload.error || 'Search failed');
            setResults(payload.results || []);
        } catch (e) {
            if (e.name !== 'AbortError') setError(e.message);
        } finally { setLoading(false); }
    }, [query, filter, serverId]);

    useEffect(() => { if (!isOpen) { setQuery(''); setResults(null); setError(''); } }, [isOpen]);

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Search Files" maxW="max-w-2xl">
            <div className="flex gap-2 mb-4">
                <input autoFocus type="text" value={query} onChange={e => setQuery(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && doSearch()}
                    className="flex-1 bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500"
                    placeholder="Search filename or path…" />
                <select value={filter} onChange={e => setFilter(e.target.value)}
                    className="bg-neutral-950 border border-neutral-700 rounded-lg px-3 py-2 text-sm text-neutral-300 focus:outline-none">
                    <option value="all">All</option>
                    <option value="files">Files only</option>
                    <option value="folders">Folders only</option>
                </select>
                <button onClick={doSearch} disabled={loading || !query.trim()} className="bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white rounded-lg px-4 py-2 text-sm font-bold transition-colors flex items-center gap-2">
                    {loading ? <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div> : <i className="bi bi-search"></i>}
                    Search
                </button>
            </div>
            {error && <div className="text-sm text-red-400 mb-3">{error}</div>}
            {results && (
                <div className="max-h-80 overflow-y-auto rounded-lg border border-neutral-800 divide-y divide-neutral-800/50">
                    {results.length === 0 && <div className="p-8 text-center text-neutral-500 text-sm">No results found.</div>}
                    {results.map((r, i) => {
                        const parent = r.path.split('/').slice(0, -1).join('/') || '/';
                        return (
                            <div key={i} className="px-4 py-3 hover:bg-neutral-800/40 transition-colors">
                                <div className="flex items-center gap-2 min-w-0">
                                    <i className={`bi ${r.isDirectory ? 'bi-folder-fill text-amber-400' : 'bi-file-earmark text-neutral-400'} shrink-0`}></i>
                                    <span className="text-sm font-semibold text-neutral-200 truncate">{r.name}</span>
                                    {r.isDirectory
                                        ? <button onClick={() => { onNavigate(r.path); onClose(); }} className="ml-auto shrink-0 text-xs text-primary-400 hover:underline">Open</button>
                                        : <a href={`/server/${serverId}/files/edit?path=${encodeURIComponent(r.path)}`} className="ml-auto shrink-0 text-xs text-primary-400 hover:underline">Edit</a>
                                    }
                                </div>
                                <button onClick={() => { onNavigate(parent); onClose(); }} className="text-xs text-neutral-500 hover:text-neutral-300 mt-0.5 truncate text-left">{r.path}</button>
                            </div>
                        );
                    })}
                </div>
            )}
        </Modal>
    );
}

// ─── SFTP Modal ────────────────────────────────────────────────────
function SftpModal({ isOpen, onClose, sftpDetails }) {
    const d = sftpDetails || {};
    return (
        <Modal isOpen={isOpen} onClose={onClose} title="SFTP Details">
            <div className="space-y-3 mb-6">
                {[['Host', d.host || '—'], ['Port', d.port || '—'], ['Username', d.username || '—']].map(([label, val]) => (
                    <div key={label} className="flex justify-between items-center border-b border-neutral-800 pb-3">
                        <span className="text-xs font-bold text-neutral-500 uppercase tracking-widest">{label}</span>
                        <span className="text-sm font-mono text-neutral-200">{val}</span>
                    </div>
                ))}
                <div className="flex justify-between items-start">
                    <span className="text-xs font-bold text-neutral-500 uppercase tracking-widest">Password</span>
                    <span className="text-xs text-neutral-400">{d.passwordHint || 'Use your panel password'}</span>
                </div>
            </div>
            {d.host && d.port && (
                <div className="bg-neutral-950 rounded-lg p-3 font-mono text-xs text-neutral-400 break-all select-all">
                    sftp://{d.username}@{d.host}:{d.port}
                </div>
            )}
        </Modal>
    );
}

// ─── Bulk Actions Bar ──────────────────────────────────────────────
function BulkBar({ selected, writeLocked, onBulkDelete, onBulkRename, onBulkChmod, onBulkArchive, onClear }) {
    if (selected.size === 0) return null;
    return (
        <div className="sticky top-0 z-30 bg-primary-950/90 backdrop-blur-md border border-primary-800/50 rounded-xl px-4 py-3 mb-4 flex items-center gap-3 flex-wrap shadow-xl shadow-primary-900/20">
            <span className="text-sm font-black text-primary-300">{selected.size} selected</span>
            <div className="flex-1 h-px bg-primary-800/30"></div>
            {!writeLocked && (
                <>
                    <button onClick={onBulkRename} className="flex items-center gap-2 text-xs font-bold text-neutral-300 hover:text-white bg-neutral-800/80 hover:bg-neutral-700 px-3 py-1.5 rounded-lg transition-colors">
                        <i className="bi bi-input-cursor-text"></i> Rename
                    </button>
                    <button onClick={onBulkChmod} className="flex items-center gap-2 text-xs font-bold text-neutral-300 hover:text-white bg-neutral-800/80 hover:bg-neutral-700 px-3 py-1.5 rounded-lg transition-colors">
                        <i className="bi bi-shield-check"></i> CHMOD
                    </button>
                    <button onClick={onBulkArchive} className="flex items-center gap-2 text-xs font-bold text-neutral-300 hover:text-white bg-neutral-800/80 hover:bg-neutral-700 px-3 py-1.5 rounded-lg transition-colors">
                        <i className="bi bi-file-zip text-yellow-400"></i> Archive
                    </button>
                    <button onClick={onBulkDelete} className="flex items-center gap-2 text-xs font-bold text-red-400 hover:text-white bg-red-900/20 hover:bg-red-900/40 px-3 py-1.5 rounded-lg transition-colors border border-red-900/30">
                        <i className="bi bi-trash3"></i> Delete {selected.size}
                    </button>
                </>
            )}
            <button onClick={onClear} className="text-xs text-neutral-500 hover:text-white transition-colors ml-auto"><i className="bi bi-x-lg"></i></button>
        </div>
    );
}

// ─── Bulk Modals ───────────────────────────────────────────────────
function BulkRenameModal({ isOpen, onClose, serverId, currentPath, selectedNames, onComplete }) {
    const [prefix, setPrefix] = useState('');
    const [suffix, setSuffix] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    useEffect(() => { if (isOpen) { setPrefix(''); setSuffix(''); setError(''); } }, [isOpen]);

    const doRename = async () => {
        if (!prefix && !suffix) return;
        setLoading(true); setError('');
        const files = [...selectedNames].map(n => ({ from: n, to: `${prefix}${n}${suffix}` }));
        try {
            const res = await fetch(`/api/client/servers/${serverId}/files/rename`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, files })
            });
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Rename failed');
            onComplete(); onClose();
        } catch (e) { setError(e.message); } finally { setLoading(false); }
    };
    return (
        <Modal isOpen={isOpen} onClose={onClose} title={`Bulk Rename (${selectedNames.size} items)`}>
            {error && <div className="text-sm text-red-400 mb-4">{error}</div>}
            <div className="space-y-4 mb-6">
                <div>
                    <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1.5">Add Prefix</label>
                    <input type="text" value={prefix} onChange={e => setPrefix(e.target.value)} placeholder="e.g. backup_" className="w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" />
                </div>
                <div>
                    <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1.5">Add Suffix</label>
                    <input type="text" value={suffix} onChange={e => setSuffix(e.target.value)} placeholder="e.g. .bak" className="w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2 text-sm text-neutral-200 focus:outline-none focus:border-primary-500" />
                </div>
                {[...selectedNames].slice(0, 3).map(n => (
                    <div key={n} className="text-xs font-mono text-neutral-500">
                        {n} <span className="text-neutral-600">→</span> <span className="text-primary-400">{prefix}{n}{suffix}</span>
                    </div>
                ))}
                {selectedNames.size > 3 && <div className="text-xs text-neutral-600">…and {selectedNames.size - 3} more</div>}
            </div>
            <div className="flex justify-end gap-3">
                <button onClick={onClose} className="text-sm text-neutral-500 hover:text-white px-4">Cancel</button>
                <button onClick={doRename} disabled={loading || (!prefix && !suffix)} className="bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2">
                    {loading && <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>}
                    Apply
                </button>
            </div>
        </Modal>
    );
}

function BulkChmodModal({ isOpen, onClose, serverId, currentPath, selectedNames, onComplete }) {
    const [mode, setMode] = useState('755');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    useEffect(() => { if (isOpen) { setMode('755'); setError(''); } }, [isOpen]);

    const doChmod = async () => {
        setLoading(true); setError('');
        const files = [...selectedNames].map(n => ({ file: n, mode }));
        try {
            const res = await fetch(`/api/client/servers/${serverId}/files/chmod`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, files })
            });
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'CHMOD failed');
            onComplete(); onClose();
        } catch (e) { setError(e.message); } finally { setLoading(false); }
    };
    return (
        <Modal isOpen={isOpen} onClose={onClose} title={`Bulk CHMOD (${selectedNames.size} items)`} maxW="max-w-sm">
            {error && <div className="text-sm text-red-400 mb-4">{error}</div>}
            <div className="mb-6">
                <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-2">Octal Mode</label>
                <input autoFocus type="text" value={mode} onChange={e => setMode(e.target.value.replace(/[^0-7]/g, '').slice(0, 4))} placeholder="755" className="w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 font-mono text-neutral-200 focus:outline-none focus:border-primary-500" />
            </div>
            <div className="flex justify-end gap-3">
                <button onClick={onClose} className="text-sm text-neutral-500 hover:text-white px-4">Cancel</button>
                <button onClick={doChmod} disabled={loading} className="bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2">
                    {loading && <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>}
                    Apply to {selectedNames.size}
                </button>
            </div>
        </Modal>
    );
}

function ArchiveModal({ isOpen, onClose, serverId, currentPath, targetNames, onComplete }) {
    const [name, setName] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    useEffect(() => {
        if (isOpen) {
            const base = [...targetNames][0] || 'archive';
            setName(targetNames.size === 1 ? `${base}.zip` : 'archive.zip');
            setError('');
        }
    }, [isOpen, targetNames]);

    const doArchive = async () => {
        if (!name.trim()) return;
        setLoading(true); setError('');
        try {
            const res = await fetch(`/api/client/servers/${serverId}/files/archive`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, files: [...targetNames], name: name.trim() })
            });
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Archive failed');
            onComplete(); onClose();
        } catch (e) { setError(e.message); } finally { setLoading(false); }
    };
    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Create Archive" maxW="max-w-sm">
            {error && <div className="text-sm text-red-400 mb-4">{error}</div>}
            <div className="mb-6">
                <label className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-2">Archive Name</label>
                <input autoFocus type="text" value={name} onChange={e => setName(e.target.value)} placeholder="archive.zip" className="w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 text-neutral-200 focus:outline-none focus:border-primary-500" />
                <div className="text-xs text-neutral-600 mt-2">{targetNames.size} item(s) → {name || 'archive.zip'}</div>
            </div>
            <div className="flex justify-end gap-3">
                <button onClick={onClose} className="text-sm text-neutral-500 hover:text-white px-4">Cancel</button>
                <button onClick={doArchive} disabled={loading || !name.trim()} className="bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2">
                    {loading && <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>}
                    Create
                </button>
            </div>
        </Modal>
    );
}

function DeleteModal({ isOpen, onClose, serverId, currentPath, targetNames, onComplete }) {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    useEffect(() => { if (isOpen) setError(''); }, [isOpen]);

    const doDelete = async () => {
        setLoading(true); setError('');
        try {
            const res = await fetch(`/api/client/servers/${serverId}/files/delete`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, files: [...targetNames] })
            });
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Delete failed');
            onComplete(); onClose();
        } catch (e) { setError(e.message); } finally { setLoading(false); }
    };
    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Confirm Delete" maxW="max-w-sm">
            {error && <div className="text-sm text-red-400 mb-4">{error}</div>}
            <div className="bg-red-950/20 border border-red-900/30 rounded-xl px-4 py-3 mb-6 text-sm text-red-300">
                <i className="bi bi-exclamation-triangle-fill mr-2 text-red-500"></i>
                This action is <strong>permanent</strong> and cannot be undone.
                <div className="mt-2 font-mono text-xs text-red-400/80">{[...targetNames].slice(0, 5).join(', ')}{targetNames.size > 5 ? ` …+${targetNames.size - 5} more` : ''}</div>
            </div>
            <div className="flex justify-end gap-3">
                <button onClick={onClose} className="text-sm text-neutral-500 hover:text-white px-4">Cancel</button>
                <button onClick={doDelete} disabled={loading} className="bg-red-600 hover:bg-red-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2">
                    {loading && <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>}
                    Delete {targetNames.size} {targetNames.size === 1 ? 'item' : 'items'}
                </button>
            </div>
        </Modal>
    );
}

function RenameModal({ isOpen, onClose, serverId, currentPath, targetName, onComplete }) {
    const [val, setVal] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    useEffect(() => { if (isOpen) { setVal(targetName || ''); setError(''); } }, [isOpen, targetName]);

    const doRename = async () => {
        if (!val.trim() || val === targetName) return;
        setLoading(true); setError('');
        try {
            const res = await fetch(`/api/client/servers/${serverId}/files/rename`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, files: [{ from: targetName, to: val.trim() }] })
            });
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Rename failed');
            onComplete(); onClose();
        } catch (e) { setError(e.message); } finally { setLoading(false); }
    };
    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Rename" maxW="max-w-sm">
            {error && <div className="text-sm text-red-400 mb-4">{error}</div>}
            <input autoFocus type="text" value={val} onChange={e => setVal(e.target.value)} onKeyDown={e => e.key === 'Enter' && doRename()} className="w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 text-neutral-200 mb-6 focus:outline-none focus:border-primary-500" />
            <div className="flex justify-end gap-3">
                <button onClick={onClose} className="text-sm text-neutral-500 hover:text-white px-4">Cancel</button>
                <button onClick={doRename} disabled={loading || !val.trim() || val === targetName} className="bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2">
                    {loading && <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>}Rename
                </button>
            </div>
        </Modal>
    );
}

function ChmodModal({ isOpen, onClose, serverId, currentPath, targetName, currentPerms, onComplete }) {
    const [mode, setMode] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    useEffect(() => { if (isOpen) { setMode(currentPerms || '755'); setError(''); } }, [isOpen, currentPerms]);

    const doChmod = async () => {
        setLoading(true); setError('');
        try {
            const res = await fetch(`/api/client/servers/${serverId}/files/chmod`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, files: [{ file: targetName, mode }] })
            });
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'CHMOD failed');
            onComplete(); onClose();
        } catch (e) { setError(e.message); } finally { setLoading(false); }
    };
    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Change Permissions" maxW="max-w-xs">
            {error && <div className="text-sm text-red-400 mb-4">{error}</div>}
            <div className="mb-2"><div className="text-xs text-neutral-500 font-mono truncate mb-3">{targetName}</div>
                <input autoFocus type="text" value={mode} onChange={e => setMode(e.target.value.replace(/[^0-7]/g, '').slice(0, 4))} onKeyDown={e => e.key === 'Enter' && doChmod()} placeholder="755" className="w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 font-mono text-neutral-200 mb-6 focus:outline-none focus:border-primary-500" /></div>
            <div className="flex justify-end gap-3">
                <button onClick={onClose} className="text-sm text-neutral-500 hover:text-white px-4">Cancel</button>
                <button onClick={doChmod} disabled={loading} className="bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2">
                    {loading && <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>}Apply
                </button>
            </div>
        </Modal>
    );
}

function CreateFolderModal({ isOpen, onClose, serverId, currentPath, onComplete }) {
    const [name, setName] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    useEffect(() => { if (isOpen) { setName(''); setError(''); } }, [isOpen]);

    const doCreate = async () => {
        if (!name.trim()) return;
        setLoading(true); setError('');
        try {
            const res = await fetch(`/api/client/servers/${serverId}/files/create-folder`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, name: name.trim() })
            });
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Failed');
            onComplete(); onClose();
        } catch (e) { setError(e.message); } finally { setLoading(false); }
    };
    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Create Folder" maxW="max-w-sm">
            {error && <div className="text-sm text-red-400 mb-4">{error}</div>}
            <input autoFocus type="text" value={name} onChange={e => setName(e.target.value)} onKeyDown={e => e.key === 'Enter' && doCreate()} placeholder="folder-name" className="w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 text-neutral-200 mb-2 focus:outline-none focus:border-primary-500" />
            <div className="text-xs text-neutral-600 mb-6">Will be created in {currentPath}</div>
            <div className="flex justify-end gap-3">
                <button onClick={onClose} className="text-sm text-neutral-500 hover:text-white px-4">Cancel</button>
                <button onClick={doCreate} disabled={loading || !name.trim()} className="bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors flex items-center gap-2">
                    {loading && <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>}Create
                </button>
            </div>
        </Modal>
    );
}

function CreateFileModal({ isOpen, onClose, currentPath, editUrlBase }) {
    const [name, setName] = useState('');
    useEffect(() => { if (isOpen) setName(''); }, [isOpen]);

    const doCreate = () => {
        if (!name.trim()) return;
        const p = (currentPath === '/' ? '' : currentPath) + '/' + name.trim();
        window.location.href = `${editUrlBase}?path=${encodeURIComponent(p)}`;
    };
    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Create File" maxW="max-w-sm">
            <input autoFocus type="text" value={name} onChange={e => setName(e.target.value)} onKeyDown={e => e.key === 'Enter' && doCreate()} placeholder="filename.yml" className="w-full bg-neutral-950 border border-neutral-700 rounded-lg px-4 py-2.5 text-neutral-200 mb-2 focus:outline-none focus:border-primary-500" />
            <div className="text-xs text-neutral-600 mb-6">Opens in editor instantly after creation.</div>
            <div className="flex justify-end gap-3">
                <button onClick={onClose} className="text-sm text-neutral-500 hover:text-white px-4">Cancel</button>
                <button onClick={doCreate} disabled={!name.trim()} className="bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white text-sm font-bold px-5 py-2 rounded-lg transition-colors">Open in Editor</button>
            </div>
        </Modal>
    );
}

// ─── Media Viewer ─────────────────────────────────────────────────
function MediaViewer({ isOpen, onClose, src, fileName, kind, serverId }) {
    if (!isOpen) return null;
    const downloadUrl = src;
    return (
        <div className="fixed inset-0 z-[300] bg-black/90 backdrop-blur-md flex flex-col" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
            <div className="flex items-center justify-between px-6 py-4 border-b border-neutral-800 shrink-0">
                <div className="flex items-center gap-3">
                    <i className={`bi ${kind === 'video' ? 'bi-play-btn' : 'bi-image'} text-neutral-400`}></i>
                    <span className="text-sm font-bold text-neutral-200 font-mono">{fileName}</span>
                </div>
                <div className="flex items-center gap-3">
                    <a href={downloadUrl} download={fileName} className="text-xs text-neutral-400 hover:text-white border border-neutral-700 rounded px-3 py-1.5 transition-colors"><i className="bi bi-download mr-1"></i>Download</a>
                    <button onClick={onClose} className="w-8 h-8 flex items-center justify-center rounded text-neutral-400 hover:text-white hover:bg-neutral-800"><i className="bi bi-x-lg"></i></button>
                </div>
            </div>
            <div className="flex-1 flex items-center justify-center p-8 overflow-auto">
                {kind === 'image' ? (
                    <img src={src} alt={fileName} className="max-w-full max-h-full object-contain rounded-xl shadow-2xl" />
                ) : (
                    <video src={src} controls autoPlay className="max-w-full max-h-full rounded-xl shadow-2xl" />
                )}
            </div>
        </div>
    );
}

// ─── Upload Queue ─────────────────────────────────────────────────
function UploadQueue({ queue, onClear }) {
    const [collapsed, setCollapsed] = useState(false);
    if (queue.length === 0) return null;
    const done = queue.filter(f => f.status === 'done').length;
    const uploading = queue.filter(f => f.status === 'uploading').length;
    return (
        <div className="fixed bottom-6 right-6 z-[100] w-80 bg-neutral-900 border border-neutral-700 rounded-2xl shadow-2xl overflow-hidden">
            <div className="px-4 py-3 border-b border-neutral-800 flex items-center justify-between cursor-pointer hover:bg-neutral-800/50 transition-colors" onClick={() => setCollapsed(c => !c)}>
                <div className="flex items-center gap-2.5">
                    <div className="relative">
                        <i className="bi bi-cloud-arrow-up text-lg text-primary-500"></i>
                        {uploading > 0 && <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-primary-500 rounded-full animate-ping"></span>}
                    </div>
                    <div>
                        <div className="text-[9px] font-black text-neutral-500 uppercase tracking-widest leading-none mb-0.5">Upload Queue</div>
                        <div className="text-xs font-bold text-white leading-none">{done}/{queue.length} uploaded</div>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    <i className={`bi ${collapsed ? 'bi-chevron-up' : 'bi-chevron-down'} text-neutral-500 text-xs`}></i>
                    <button onClick={e => { e.stopPropagation(); onClear(); }} className="text-neutral-500 hover:text-white transition-colors text-xs"><i className="bi bi-x-lg"></i></button>
                </div>
            </div>
            {!collapsed && (
                <div className="max-h-60 overflow-y-auto divide-y divide-neutral-800/50">
                    {queue.map(item => (
                        <div key={item.id} className="px-4 py-3">
                            <div className="flex justify-between items-start gap-2 mb-1.5">
                                <span className="text-xs font-bold text-neutral-200 truncate flex-1">{item.name}</span>
                                {item.status === 'done' && <i className="bi bi-check-circle-fill text-green-500 shrink-0"></i>}
                                {item.status === 'error' && <i className="bi bi-exclamation-circle-fill text-red-500 shrink-0"></i>}
                                {item.status === 'uploading' && <span className="text-[10px] font-black text-primary-500 shrink-0">{item.progress}%</span>}
                            </div>
                            {item.status === 'uploading' && (
                                <div className="h-1 w-full bg-neutral-800 rounded-full overflow-hidden">
                                    <div className="h-full bg-primary-500 transition-all rounded-full" style={{ width: `${item.progress}%` }}></div>
                                </div>
                            )}
                            {item.status === 'error' && <div className="text-[10px] text-red-400 truncate">{item.error}</div>}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

// ─── Context Menu ─────────────────────────────────────────────────
function ContextMenu({ x, y, entry, entryPath, writeLocked, canDownload, editUrlBase, previewUrlBase, downloadUrlBase, currentPath, serverId, onClose, onRename, onChmod, onArchive, onUnarchive, onDelete, onNavigate }) {
    const ref = useRef(null);
    useEffect(() => {
        const handle = () => onClose();
        const delay = setTimeout(() => window.addEventListener('click', handle), 50);
        return () => { clearTimeout(delay); window.removeEventListener('click', handle); };
    }, []);

    const style = { position: 'fixed', top: y, left: x, zIndex: 500 };

    const Item = ({ icon, label, onClick, danger, iconClass }) => (
        <button onClick={() => { onClick(); onClose(); }} className={`w-full text-left flex items-center gap-2.5 px-3 py-2 text-sm rounded-lg transition-colors ${danger ? 'text-red-400 hover:bg-red-900/20 hover:text-red-300' : 'text-neutral-300 hover:bg-neutral-800 hover:text-white'}`}>
            <i className={`bi ${icon} text-sm ${iconClass || ''}`}></i> {label}
        </button>
    );
    const Sep = () => <div className="my-1 h-px bg-neutral-800"></div>;

    return (
        <div ref={ref} style={style} className="w-52 bg-neutral-950/95 backdrop-blur-xl border border-neutral-800 rounded-xl shadow-2xl py-1.5 px-1">
            {entry.isDirectory ? (
                <Item icon="bi-folder-symlink" label="Open Folder" onClick={() => onNavigate(entryPath)} iconClass="text-amber-400" />
            ) : (
                <>
                    <Item icon="bi-pencil" label="Edit File" onClick={() => { window.location.href = `${editUrlBase}?path=${encodeURIComponent(entryPath)}`; }} />
                    <Item icon="bi-eye" label="Preview" onClick={() => { window.location.href = `${previewUrlBase}?path=${encodeURIComponent(entryPath)}`; }} />
                    {canDownload && <Item icon="bi-cloud-arrow-down" label="Download" onClick={() => { window.open(`${downloadUrlBase}?path=${encodeURIComponent(entryPath)}`); }} iconClass="text-blue-400" />}
                </>
            )}
            {!writeLocked && (
                <>
                    <Sep />
                    <Item icon="bi-input-cursor-text" label="Rename" onClick={() => onRename(entry.name)} />
                    <Item icon="bi-shield-check" label="Permissions" onClick={() => onChmod(entry.name, entry.permissions)} />
                    <Item icon="bi-file-zip" label="Archive" onClick={() => onArchive(new Set([entry.name]))} iconClass="text-yellow-400" />
                    {!entry.isDirectory && isArchive(entry.name) && (
                        <Item icon="bi-file-earmark-zip" label="Unarchive" onClick={() => onUnarchive(entry.name)} iconClass="text-green-400" />
                    )}
                    <Sep />
                    <Item icon="bi-trash3" label={`Delete ${entry.isDirectory ? 'Folder' : 'File'}`} onClick={() => onDelete(new Set([entry.name]))} danger />
                </>
            )}
        </div>
    );
}

// ─── Main Page ────────────────────────────────────────────────────
export function ServerFilesPage({ pageData = data }) {
    const manager = pageData.fileManager || {};
    const permissions = pageData.permissions || {};
    const sftpDetails = pageData.sftpDetails || {};

    const [currentPath, setCurrentPath] = useState(() => normalizePath(pageData.initialPath || '/'));
    const [entries, setEntries] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [selected, setSelected] = useState(new Set());
    const [isDragging, setIsDragging] = useState(false);
    const [uploadQueue, setUploadQueue] = useState([]);
    const [contextMenu, setContextMenu] = useState(null);
    const [mediaViewer, setMediaViewer] = useState(null);
    const [modal, setModal] = useState({ type: null, target: null, extra: null });

    const openModal = (type, target = null, extra = null) => setModal({ type, target, extra });
    const closeModal = () => setModal({ type: null, target: null, extra: null });

    // ── Load directory ─────────────────────────────────────────────
    const loadDir = useCallback(() => {
        let cancelled = false;
        setLoading(true); setError(''); setSelected(new Set());
        fetch(`${manager.fetchUrlBase}?path=${encodeURIComponent(currentPath)}`, {
            credentials: 'same-origin', headers: { Accept: 'application/json' }
        })
            .then(r => r.json())
            .then(payload => {
                if (cancelled) return;
                if (payload.error) throw new Error(payload.error);
                const list = (Array.isArray(payload.files) ? payload.files : []).sort((a, b) => {
                    if (a.isDirectory && !b.isDirectory) return -1;
                    if (!a.isDirectory && b.isDirectory) return 1;
                    return String(a.name || '').localeCompare(String(b.name || ''), undefined, { numeric: true, sensitivity: 'base' });
                });
                setEntries(list); setLoading(false);
            })
            .catch(e => { if (!cancelled) { setEntries([]); setLoading(false); setError(e.message || 'Failed to load files.'); } });
        return () => { cancelled = true; };
    }, [currentPath, manager.fetchUrlBase]);

    useEffect(() => loadDir(), [loadDir]);

    // ── Keyboard shortcuts ─────────────────────────────────────────
    useEffect(() => {
        const handle = (e) => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
            if (e.ctrlKey || e.metaKey) {
                if (e.key === 'f') { e.preventDefault(); openModal('search'); }
                if (e.key === 'r') { e.preventDefault(); loadDir(); }
                if (e.key === 'n' && !e.shiftKey) { e.preventDefault(); openModal('createFile'); }
                if (e.key === 'n' && e.shiftKey) { e.preventDefault(); openModal('createFolder'); }
                if (e.key === 'a') { e.preventDefault(); setSelected(new Set(entries.map(e => e.name))); }
            }
            if (e.key === 'Escape') { setSelected(new Set()); setContextMenu(null); }
        };
        window.addEventListener('keydown', handle);
        return () => window.removeEventListener('keydown', handle);
    }, [entries, loadDir]);

    // ── Upload ─────────────────────────────────────────────────────
    const uploadFile = useCallback((file, queueId) => {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            const url = `${manager.uploadUrlBase || `/server/${pageData.server?.containerId}/files/upload`}?path=${encodeURIComponent(currentPath)}&name=${encodeURIComponent(file.name)}`;
            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const pct = Math.round(e.loaded / e.total * 100);
                    setUploadQueue(prev => prev.map(i => i.id === queueId ? { ...i, progress: pct } : i));
                }
            };
            xhr.onreadystatechange = () => {
                if (xhr.readyState !== 4) return;
                try {
                    const p = JSON.parse(xhr.responseText || '{}');
                    if (xhr.status >= 200 && xhr.status < 300 && !p.error) {
                        setUploadQueue(prev => prev.map(i => i.id === queueId ? { ...i, status: 'done', progress: 100 } : i));
                        resolve();
                    } else throw new Error(p.error || 'Upload failed');
                } catch (err) {
                    setUploadQueue(prev => prev.map(i => i.id === queueId ? { ...i, status: 'error', error: err.message } : i));
                    reject(err);
                }
            };
            xhr.open('POST', url, true);
            xhr.setRequestHeader('Content-Type', 'application/octet-stream');
            xhr.setRequestHeader('x-file-name', file.name);
            xhr.withCredentials = true;
            xhr.send(file);
        });
    }, [currentPath, manager.uploadUrlBase, pageData.server?.containerId]);

    const handleFiles = useCallback(async (files) => {
        if (permissions.filesWriteLocked) return;
        const arr = Array.from(files);
        if (arr.length === 0) return;
        const newItems = arr.map(f => ({ id: Math.random().toString(36).slice(2), name: f.name, size: f.size, progress: 0, status: 'uploading' }));
        setUploadQueue(prev => [...newItems, ...prev]);
        await Promise.allSettled(arr.map((f, i) => uploadFile(f, newItems[i].id)));
        loadDir();
    }, [permissions.filesWriteLocked, uploadFile, loadDir]);

    // ── Drag & Drop ────────────────────────────────────────────────
    const handleDragOver = (e) => { e.preventDefault(); if (!permissions.filesWriteLocked) setIsDragging(true); };
    const handleDragLeave = (e) => { if (!e.currentTarget.contains(e.relatedTarget)) setIsDragging(false); };
    const handleDrop = (e) => { e.preventDefault(); setIsDragging(false); handleFiles(e.dataTransfer.files); };

    // ── Single actions ─────────────────────────────────────────────
    const handleUnarchive = async (name) => {
        setLoading(true);
        try {
            const res = await fetch(`/api/client/servers/${pageData.server?.containerId}/files/unarchive`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, name })
            });
            const p = await res.json();
            if (!res.ok || p.error) throw new Error(p.error || 'Extraction failed');
            loadDir();
        } catch (e) { setError(e.message); setLoading(false); }
    };

    // ── Entry click ────────────────────────────────────────────────
    const handleEntryClick = (entry, entryPath) => {
        if (entry.isDirectory) { setCurrentPath(entryPath); return; }
        const mk = mediaKind(entry.name);
        if (mk) {
            setMediaViewer({ src: `${manager.downloadUrlBase}?path=${encodeURIComponent(entryPath)}`, fileName: entry.name, kind: mk });
            return;
        }
        window.location.href = `${manager.editUrlBase}?path=${encodeURIComponent(entryPath)}`;
    };

    // ── Selection ──────────────────────────────────────────────────
    const toggleSelect = (name, e) => {
        e.stopPropagation();
        setSelected(prev => {
            const next = new Set(prev);
            if (next.has(name)) next.delete(name); else next.add(name);
            return next;
        });
    };
    const toggleAll = () => {
        setSelected(prev => prev.size === entries.length ? new Set() : new Set(entries.map(e => e.name)));
    };

    // ── Context Menu ───────────────────────────────────────────────
    const handleContextMenu = (e, entry, entryPath) => {
        e.preventDefault();
        // keep menu inside viewport
        const x = Math.min(e.clientX, window.innerWidth - 220);
        const y = Math.min(e.clientY, window.innerHeight - 300);
        setContextMenu({ x, y, entry, entryPath });
    };

    const breadcrumbs = buildBreadcrumbs(currentPath);
    const activeServer = pageData.server || {};
    const allSelected = entries.length > 0 && selected.size === entries.length;

    return (
        <ReactAppShell pageData={pageData} subtitle="File Manager">
            <div className="max-w-7xl mx-auto px-0 sm:px-4">
                {/* ── Top Toolbar ───────────────────────────────── */}
                <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
                    <div className="flex flex-wrap gap-2">
                        {!permissions.filesWriteLocked && (
                            <>
                                <button onClick={() => openModal('createFile')} className="flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-200 text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
                                    <i className="bi bi-file-earmark-plus"></i> New File
                                </button>
                                <button onClick={() => openModal('createFolder')} className="flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-200 text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
                                    <i className="bi bi-folder-plus"></i> New Folder
                                </button>
                                {manager.webUploadEnabled && (
                                    <button onClick={() => document.getElementById('_hiddenUpload').click()} className="flex items-center gap-2 bg-primary-600 hover:bg-primary-500 text-white text-sm font-bold px-4 py-2 rounded-lg transition-colors">
                                        <i className="bi bi-cloud-upload"></i> Upload
                                    </button>
                                )}
                                {permissions.canFixPermissions && (
                                    <form method="POST" action={`/server/${activeServer.containerId}/fix-permissions`} className="inline-flex">
                                        <button type="submit" className="flex items-center gap-2 bg-amber-900/20 hover:bg-amber-900/30 border border-amber-800/40 text-amber-300 text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
                                            <i className="bi bi-tools"></i> Fix Perms
                                        </button>
                                    </form>
                                )}
                            </>
                        )}
                        <input type="file" id="_hiddenUpload" multiple className="hidden" onChange={e => handleFiles(e.target.files)} />
                    </div>
                    <div className="flex items-center gap-2">
                        <button onClick={() => openModal('search')} className="flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-300 text-sm px-3 py-2 rounded-lg transition-colors">
                            <i className="bi bi-search"></i> <span className="hidden sm:inline">Search</span>
                        </button>
                        {sftpDetails.available && (
                            <button onClick={() => openModal('sftp')} className="flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-300 text-sm px-3 py-2 rounded-lg transition-colors">
                                <i className="bi bi-hdd-network"></i> <span className="hidden sm:inline">SFTP</span>
                            </button>
                        )}
                        <button onClick={loadDir} className="flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-300 text-sm px-3 py-2 rounded-lg transition-colors" title="Refresh (Ctrl+R)">
                            <i className="bi bi-arrow-clockwise"></i>
                        </button>
                        <a href={`${manager.legacyUrl}?legacy=1`} className="flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-400 text-xs px-3 py-2 rounded-lg transition-colors">
                            <i className="bi bi-box-arrow-up-right"></i> Legacy
                        </a>
                    </div>
                </div>

                {/* Policy warnings */}
                {permissions.filesWriteLocked && (
                    <div className="mb-4 flex items-center gap-2 px-4 py-3 bg-amber-900/10 border border-amber-800/30 text-amber-200 rounded-xl text-sm">
                        <i className="bi bi-shield-lock-fill text-amber-500"></i>
                        File writes are locked by policy. Read-only mode.
                    </div>
                )}
                {!permissions.filesWriteLocked && (pageData.policyReadOnlyPatterns || []).length > 0 && (
                    <div className="mb-4 flex items-center gap-2 px-4 py-3 bg-blue-900/10 border border-blue-800/30 text-blue-200 rounded-xl text-sm">
                        <i className="bi bi-shield-lock text-blue-400"></i>
                        Read-only pattern policy is active for {pageData.policyReadOnlyPatterns.length} path(s).
                    </div>
                )}
                {manager.webUploadEnabled && (
                    <div className="text-xs text-neutral-600 mb-3">Max upload: {manager.webUploadMaxMb} MB per file · Drag & drop anywhere below</div>
                )}

                {/* ── Bulk Bar ───────────────────────────────────── */}
                <BulkBar
                    selected={selected}
                    writeLocked={permissions.filesWriteLocked}
                    onClear={() => setSelected(new Set())}
                    onBulkDelete={() => openModal('bulkDelete', null, selected)}
                    onBulkRename={() => openModal('bulkRename', null, selected)}
                    onBulkChmod={() => openModal('bulkChmod', null, selected)}
                    onBulkArchive={() => openModal('archive', null, selected)}
                />

                {/* ── File Table ─────────────────────────────────── */}
                <div className="bg-neutral-900 border border-neutral-800 rounded-2xl overflow-hidden relative"
                    onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}
                    onContextMenu={e => { e.preventDefault(); setContextMenu(null); }}>

                    {isDragging && (
                        <div className="absolute inset-0 z-50 bg-primary-600/10 border-2 border-dashed border-primary-500 rounded-2xl flex items-center justify-center pointer-events-none">
                            <div className="bg-neutral-950 rounded-2xl px-12 py-10 shadow-2xl border border-neutral-700 flex flex-col items-center">
                                <i className="bi bi-cloud-arrow-up text-5xl text-primary-500 mb-3"></i>
                                <span className="text-xl font-black text-white uppercase tracking-wider">Drop to Upload</span>
                                <span className="text-xs text-neutral-500 mt-2">into {currentPath}</span>
                            </div>
                        </div>
                    )}

                    {/* Breadcrumbs */}
                    <div className="px-5 py-3 border-b border-neutral-800 bg-neutral-900/60 flex items-center flex-wrap gap-1">
                        {breadcrumbs.map((seg, idx) => (
                            <React.Fragment key={seg.path}>
                                <button type="button"
                                    onClick={() => idx !== breadcrumbs.length - 1 && setCurrentPath(seg.path)}
                                    className={`flex items-center gap-1 text-sm font-semibold transition-colors px-1 ${idx === breadcrumbs.length - 1 ? 'text-neutral-200 cursor-default' : 'text-neutral-500 hover:text-white'}`}>
                                    {seg.icon ? <i className="bi bi-house-door-fill text-base"></i> : seg.label}
                                </button>
                                {idx < breadcrumbs.length - 1 && <span className="text-neutral-700 font-bold">/</span>}
                            </React.Fragment>
                        ))}
                    </div>

                    {error && (
                        <div className="px-5 py-3 border-b border-red-900/30 bg-red-900/10 text-red-300 text-sm flex items-center gap-2">
                            <i className="bi bi-exclamation-triangle-fill text-red-500"></i> {error}
                        </div>
                    )}

                    {/* Table header */}
                    <div className="grid grid-cols-12 px-4 py-2.5 border-b border-neutral-800 bg-neutral-950/40 text-[10px] font-black text-neutral-500 uppercase tracking-widest">
                        <div className="col-span-1 flex items-center justify-center">
                            <input type="checkbox" checked={allSelected} onChange={toggleAll}
                                className="w-4 h-4 rounded border-neutral-700 bg-neutral-900 accent-primary-500 cursor-pointer" />
                        </div>
                        <div className="col-span-6">Name</div>
                        <div className="hidden md:block col-span-2">Permissions</div>
                        <div className="hidden md:block col-span-2 text-right">Size</div>
                        <div className="col-span-5 md:col-span-1 text-right">Actions</div>
                    </div>

                    {/* Body */}
                    <div className="min-h-[300px]">
                        {loading && (
                            <div className="flex justify-center items-center py-20">
                                <div className="flex flex-col items-center gap-4">
                                    <div className="w-10 h-10 border-4 border-neutral-800 border-t-primary-500 rounded-full animate-spin"></div>
                                    <span className="text-xs text-neutral-500 uppercase tracking-widest font-bold">Loading…</span>
                                </div>
                            </div>
                        )}
                        {!loading && entries.length === 0 && (
                            <div className="flex flex-col items-center justify-center py-20 text-neutral-600">
                                <i className="bi bi-folder2-open text-4xl mb-3"></i>
                                <span className="text-sm">This directory is empty</span>
                            </div>
                        )}
                        {!loading && entries.map(entry => {
                            const entryPath = normalizePath(`${currentPath === '/' ? '' : currentPath}/${entry.name}`);
                            const isSelected = selected.has(entry.name);
                            const icon = getFileIcon(entry);
                            const mk = !entry.isDirectory ? mediaKind(entry.name) : null;

                            return (
                                <div key={entryPath}
                                    onContextMenu={e => handleContextMenu(e, entry, entryPath)}
                                    className={`grid grid-cols-12 items-center px-4 py-2.5 border-b border-neutral-800/40 transition-colors group relative ${isSelected ? 'bg-primary-900/10 border-primary-900/20' : 'hover:bg-neutral-800/30'}`}>

                                    {/* Checkbox */}
                                    <div className="col-span-1 flex justify-center">
                                        <input type="checkbox" checked={isSelected} onClick={e => toggleSelect(entry.name, e)} onChange={() => {}}
                                            className="w-4 h-4 rounded border-neutral-700 bg-neutral-900 accent-primary-500 cursor-pointer" />
                                    </div>

                                    {/* Name */}
                                    <div className="col-span-6 flex items-center min-w-0">
                                        <button type="button" onClick={() => handleEntryClick(entry, entryPath)}
                                            className="flex items-center gap-3 text-left min-w-0 flex-1 py-1.5 group/name">
                                            <i className={`bi ${icon} text-xl shrink-0`}></i>
                                            <div className="min-w-0">
                                                <div className="text-sm font-semibold text-neutral-200 group-hover/name:text-white truncate transition-colors">
                                                    {entry.name}
                                                </div>
                                                {entry.isDirectory && (
                                                    <div className="text-[10px] text-neutral-600">Folder · {formatDate(entry.modified)}</div>
                                                )}
                                                {!entry.isDirectory && (
                                                    <div className="text-[10px] text-neutral-600 md:hidden">{formatBytes(entry.size)} · {entry.permissions || ''}</div>
                                                )}
                                            </div>
                                        </button>
                                    </div>

                                    {/* Permissions */}
                                    <div className="hidden md:flex col-span-2 items-center">
                                        <span className="text-xs font-mono text-neutral-500">{entry.permissions || '—'}</span>
                                    </div>

                                    {/* Size */}
                                    <div className="hidden md:flex col-span-2 items-center justify-end">
                                        <span className="text-xs font-mono text-neutral-500">
                                            {entry.isDirectory ? '—' : formatBytes(entry.size)}
                                        </span>
                                    </div>

                                    {/* Actions */}
                                    <div className="col-span-5 md:col-span-1 flex items-center justify-end gap-1">
                                        {mk && (
                                            <button onClick={() => setMediaViewer({ src: `${manager.downloadUrlBase}?path=${encodeURIComponent(entryPath)}`, fileName: entry.name, kind: mk })}
                                                className="w-7 h-7 flex items-center justify-center rounded text-neutral-600 hover:text-purple-400 hover:bg-purple-900/20 transition-colors opacity-0 group-hover:opacity-100" title="Preview">
                                                <i className="bi bi-play-circle text-sm"></i>
                                            </button>
                                        )}
                                        {!entry.isDirectory && permissions.canDownloadFiles && (
                                            <a href={`${manager.downloadUrlBase}?path=${encodeURIComponent(entryPath)}`}
                                                className="w-7 h-7 flex items-center justify-center rounded text-neutral-600 hover:text-blue-400 hover:bg-blue-900/20 transition-colors opacity-0 group-hover:opacity-100" title="Download">
                                                <i className="bi bi-cloud-arrow-down text-sm"></i>
                                            </a>
                                        )}
                                        {!permissions.filesWriteLocked && (
                                            <button onClick={() => openModal('rename', entry.name)}
                                                className="w-7 h-7 flex items-center justify-center rounded text-neutral-600 hover:text-amber-400 hover:bg-amber-900/20 transition-colors opacity-0 group-hover:opacity-100" title="Rename">
                                                <i className="bi bi-input-cursor-text text-sm"></i>
                                            </button>
                                        )}
                                        {!permissions.filesWriteLocked && (
                                            <button onClick={() => openModal('delete', null, new Set([entry.name]))}
                                                className="w-7 h-7 flex items-center justify-center rounded text-neutral-600 hover:text-red-400 hover:bg-red-900/20 transition-colors opacity-0 group-hover:opacity-100" title="Delete">
                                                <i className="bi bi-trash3 text-sm"></i>
                                            </button>
                                        )}
                                        <button onClick={e => { e.stopPropagation(); handleContextMenu(e, entry, entryPath); }}
                                            className="w-7 h-7 flex items-center justify-center rounded text-neutral-500 hover:text-white hover:bg-neutral-700 transition-colors border border-neutral-700 md:border-0" title="More">
                                            <i className="bi bi-three-dots text-sm"></i>
                                        </button>
                                    </div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Footer */}
                    <div className="px-5 py-2.5 border-t border-neutral-800 bg-neutral-950/30 flex justify-between items-center text-[10px] text-neutral-600 font-mono">
                        <span>{entries.length} item{entries.length !== 1 ? 's' : ''}</span>
                        <span className="hidden sm:inline">Ctrl+F search · Ctrl+A select all · Right-click for options</span>
                    </div>
                </div>
            </div>

            {/* ── Context Menu ──────────────────────────────────── */}
            {contextMenu && (
                <ContextMenu
                    x={contextMenu.x} y={contextMenu.y}
                    entry={contextMenu.entry} entryPath={contextMenu.entryPath}
                    writeLocked={permissions.filesWriteLocked}
                    canDownload={permissions.canDownloadFiles}
                    editUrlBase={manager.editUrlBase}
                    previewUrlBase={manager.previewUrlBase}
                    downloadUrlBase={manager.downloadUrlBase}
                    currentPath={currentPath}
                    serverId={activeServer.containerId}
                    onClose={() => setContextMenu(null)}
                    onRename={name => openModal('rename', name)}
                    onChmod={(name, perms) => openModal('chmod', name, perms)}
                    onArchive={names => openModal('archive', null, names)}
                    onUnarchive={name => handleUnarchive(name)}
                    onDelete={names => openModal('delete', null, names)}
                    onNavigate={path => setCurrentPath(path)}
                />
            )}

            {/* ── Modals ────────────────────────────────────────── */}
            <SearchModal isOpen={modal.type === 'search'} onClose={closeModal} serverId={activeServer.containerId} onNavigate={setCurrentPath} />
            <SftpModal isOpen={modal.type === 'sftp'} onClose={closeModal} sftpDetails={sftpDetails} />
            <CreateFileModal isOpen={modal.type === 'createFile'} onClose={closeModal} currentPath={currentPath} editUrlBase={manager.editUrlBase} />
            <CreateFolderModal isOpen={modal.type === 'createFolder'} onClose={closeModal} serverId={activeServer.containerId} currentPath={currentPath} onComplete={loadDir} />
            <RenameModal isOpen={modal.type === 'rename'} onClose={closeModal} serverId={activeServer.containerId} currentPath={currentPath} targetName={modal.target} onComplete={loadDir} />
            <ChmodModal isOpen={modal.type === 'chmod'} onClose={closeModal} serverId={activeServer.containerId} currentPath={currentPath} targetName={modal.target} currentPerms={modal.extra} onComplete={loadDir} />
            <DeleteModal isOpen={modal.type === 'delete'} onClose={closeModal} serverId={activeServer.containerId} currentPath={currentPath} targetNames={modal.extra || new Set()} onComplete={loadDir} />
            <ArchiveModal isOpen={modal.type === 'archive'} onClose={closeModal} serverId={activeServer.containerId} currentPath={currentPath} targetNames={modal.extra || new Set()} onComplete={loadDir} />
            <BulkRenameModal isOpen={modal.type === 'bulkRename'} onClose={closeModal} serverId={activeServer.containerId} currentPath={currentPath} selectedNames={modal.extra || new Set()} onComplete={() => { loadDir(); setSelected(new Set()); }} />
            <BulkChmodModal isOpen={modal.type === 'bulkChmod'} onClose={closeModal} serverId={activeServer.containerId} currentPath={currentPath} selectedNames={modal.extra || new Set()} onComplete={() => { loadDir(); setSelected(new Set()); }} />

            {/* ── Media Viewer ──────────────────────────────────── */}
            {mediaViewer && (
                <MediaViewer isOpen={true} onClose={() => setMediaViewer(null)}
                    src={mediaViewer.src} fileName={mediaViewer.fileName} kind={mediaViewer.kind}
                    serverId={activeServer.containerId} />
            )}

            {/* ── Upload Queue ──────────────────────────────────── */}
            <UploadQueue queue={uploadQueue} onClear={() => setUploadQueue([])} />
        </ReactAppShell>
    );
}

export default ServerFilesPage;

if (root) {
    root.render(<ServerFilesPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
