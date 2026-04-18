import React, { useState, useEffect, useRef, useCallback } from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-file-editor';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

// ─── Language Detection ────────────────────────────────────────────
const EXT_LANG_MAP = {
    js: 'javascript', mjs: 'javascript', cjs: 'javascript',
    ts: 'typescript', tsx: 'typescript',
    jsx: 'javascript',
    json: 'json', jsonc: 'json',
    yaml: 'yaml', yml: 'yaml',
    toml: 'ini',
    xml: 'xml', html: 'html', htm: 'html',
    css: 'css', scss: 'scss', less: 'less',
    sh: 'shell', bash: 'shell', zsh: 'shell',
    py: 'python', rb: 'ruby', php: 'php',
    java: 'java', kt: 'kotlin', rs: 'rust',
    go: 'go', cs: 'csharp', cpp: 'cpp', c: 'c', h: 'cpp',
    sql: 'sql',
    md: 'markdown', mdx: 'markdown',
    ini: 'ini', conf: 'ini', cfg: 'ini', env: 'ini',
    lua: 'lua', properties: 'ini',
    dockerfile: 'dockerfile',
    tf: 'hcl', groovy: 'groovy', gradle: 'groovy',
};

function detectLanguage(fileName = '') {
    const base = fileName.split('/').pop().toLowerCase();
    if (base === 'dockerfile' || base === '.env') return base === 'dockerfile' ? 'dockerfile' : 'ini';
    const ext = base.split('.').pop();
    return EXT_LANG_MAP[ext] || 'plaintext';
}

// ─── Monaco Loader ────────────────────────────────────────────────
let monacoLoadPromise = null;
function loadMonaco() {
    if (monacoLoadPromise) return monacoLoadPromise;
    monacoLoadPromise = new Promise((resolve) => {
        if (window.monaco) { resolve(window.monaco); return; }
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/monaco-editor@0.46.0/min/vs/loader.js';
        script.onload = () => {
            window.require.config({
                paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.46.0/min/vs' }
            });
            window.require(['vs/editor/editor.main'], (monaco) => {
                window.monaco = monaco;
                resolve(monaco);
            });
        };
        document.head.appendChild(script);
    });
    return monacoLoadPromise;
}

// ─── File Tree Item ───────────────────────────────────────────────
function FileTreeItem({ item, currentPath, onFileSwitch, serverId, depth = 0 }) {
    const [isExpanded, setIsExpanded] = useState(false);
    const [children, setChildren] = useState([]);
    const [loading, setLoading] = useState(false);

    const fullPath = (item.directory === '/' ? '' : item.directory) + '/' + item.name;
    const isActive = fullPath === currentPath;

    const handleClick = async () => {
        if (!item.isDirectory) { onFileSwitch(fullPath); return; }
        const next = !isExpanded;
        setIsExpanded(next);
        if (next && children.length === 0) {
            setLoading(true);
            try {
                const res = await fetch(`/api/client/servers/${serverId}/files/list?path=${encodeURIComponent(fullPath)}`, {
                    headers: { Accept: 'application/json' }, credentials: 'same-origin'
                });
                const payload = await res.json();
                if (payload.files) {
                    setChildren(payload.files.sort((a, b) => {
                        if (a.isDirectory && !b.isDirectory) return -1;
                        if (!a.isDirectory && b.isDirectory) return 1;
                        return a.name.localeCompare(b.name);
                    }));
                }
            } catch (e) { /* ignore */ } finally { setLoading(false); }
        }
    };

    return (
        <div>
            <div
                onClick={handleClick}
                style={{ paddingLeft: `${(depth * 14) + 10}px` }}
                className={`flex items-center gap-2 py-[5px] pr-2 cursor-pointer rounded transition-colors select-none text-[12px] ${isActive ? 'bg-primary-900/30 text-primary-300 font-semibold' : 'hover:bg-neutral-800/50 text-neutral-400 hover:text-neutral-200'}`}
            >
                {item.isDirectory ? (
                    <i className={`bi ${isExpanded ? 'bi-chevron-down text-[9px] text-neutral-500' : 'bi-chevron-right text-[9px] text-neutral-500'} w-3 shrink-0`}></i>
                ) : (
                    <span className="w-3 shrink-0"></span>
                )}
                <i className={`bi ${item.isDirectory ? (isExpanded ? 'bi-folder2-open text-amber-400/80' : 'bi-folder-fill text-amber-500/70') : 'bi-file-earmark-text text-neutral-500'} shrink-0`}></i>
                <span className="truncate min-w-0 flex-1">{item.name}</span>
                {loading && <div className="w-2 h-2 border border-t-primary-500 border-neutral-700 rounded-full animate-spin shrink-0"></div>}
            </div>
            {item.isDirectory && isExpanded && (
                <div>
                    {children.map(child => (
                        <FileTreeItem key={`${fullPath}/${child.name}`} item={{ ...child, directory: fullPath }}
                            currentPath={currentPath} onFileSwitch={onFileSwitch} serverId={serverId} depth={depth + 1} />
                    ))}
                    {children.length === 0 && !loading && (
                        <div style={{ paddingLeft: `${((depth + 1) * 14) + 23}px` }} className="text-[10px] text-neutral-600 italic py-1">empty</div>
                    )}
                </div>
            )}
        </div>
    );
}

// ─── Main Editor Page ─────────────────────────────────────────────
export function ServerFileEditorPage({ pageData = data }) {
    const server = pageData.server || {};
    const urlParams = new URLSearchParams(window.location.search);
    const filePath = urlParams.get('path') || pageData.filePath || '/';
    const fileName = filePath.split('/').pop() || 'file';
    const parentPath = filePath.split('/').slice(0, -1).join('/') || '/';
    const language = detectLanguage(fileName);

    const [content, setContent] = useState('');
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [status, setStatus] = useState({ type: 'idle', message: '' });
    const [isUnsaved, setIsUnsaved] = useState(false);
    const [editorMode, setEditorMode] = useState('monaco'); // 'monaco' | 'plain'
    const [sidebarOpen, setSidebarOpen] = useState(true);
    const [wordWrap, setWordWrap] = useState(false);
    const [rootFiles, setRootFiles] = useState([]);
    const [rootLoading, setRootLoading] = useState(false);
    const [monacoReady, setMonacoReady] = useState(false);
    const [cursorInfo, setCursorInfo] = useState({ line: 1, col: 1 });

    const editorContainerRef = useRef(null);
    const monacoEditorRef = useRef(null);
    const monacoRef = useRef(null);
    const contentRef = useRef(content);
    contentRef.current = content;

    // ── Load file content ──────────────────────────────────────────
    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setStatus({ type: 'idle', message: '' });
        fetch(`/api/client/servers/${server.containerId}/files/content?path=${encodeURIComponent(filePath)}`, {
            headers: { Accept: 'application/json' }, credentials: 'same-origin'
        })
            .then(r => r.json())
            .then(payload => {
                if (cancelled) return;
                if (payload.error) throw new Error(payload.error);
                setContent(payload.content || '');
                setLoading(false);
                setIsUnsaved(false);
            })
            .catch(err => {
                if (cancelled) return;
                setStatus({ type: 'error', message: err.message || 'Failed to load file.' });
                setLoading(false);
            });

        setRootLoading(true);
        fetch(`/api/client/servers/${server.containerId}/files/list?path=/`, {
            headers: { Accept: 'application/json' }, credentials: 'same-origin'
        })
            .then(r => r.json())
            .then(payload => {
                if (cancelled) return;
                if (payload.files) {
                    setRootFiles(payload.files.sort((a, b) => {
                        if (a.isDirectory && !b.isDirectory) return -1;
                        if (!a.isDirectory && b.isDirectory) return 1;
                        return a.name.localeCompare(b.name);
                    }));
                }
                setRootLoading(false);
            })
            .catch(() => { if (!cancelled) setRootLoading(false); });

        return () => { cancelled = true; };
    }, [server.containerId, filePath]);

    // ── Monaco initialization ──────────────────────────────────────
    useEffect(() => {
        if (editorMode !== 'monaco' || loading) return;
        if (!editorContainerRef.current) return;

        let destroyed = false;
        loadMonaco().then(monaco => {
            if (destroyed || !editorContainerRef.current) return;
            monacoRef.current = monaco;

            if (monacoEditorRef.current) {
                monacoEditorRef.current.setValue(contentRef.current);
                monacoEditorRef.current.updateOptions({ wordWrap: wordWrap ? 'on' : 'off', readOnly: Boolean(pageData.editWriteLocked) });
                return;
            }

            const editor = monaco.editor.create(editorContainerRef.current, {
                value: contentRef.current,
                language,
                theme: 'vs-dark',
                fontSize: 14,
                fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
                fontLigatures: true,
                lineNumbers: 'on',
                minimap: { enabled: true },
                scrollBeyondLastLine: false,
                wordWrap: wordWrap ? 'on' : 'off',
                tabSize: 4,
                insertSpaces: true,
                automaticLayout: true,
                padding: { top: 16 },
                readOnly: Boolean(pageData.editWriteLocked),
                renderLineHighlight: 'all',
                cursorBlinking: 'smooth',
                smoothScrolling: true,
                bracketPairColorization: { enabled: true },
            });

            editor.onDidChangeModelContent(() => {
                if (!destroyed) {
                    setContent(editor.getValue());
                    setIsUnsaved(true);
                }
            });

            editor.onDidChangeCursorPosition((e) => {
                if (!destroyed) {
                    setCursorInfo({ line: e.position.lineNumber, col: e.position.column });
                }
            });

            // Ctrl+S to save
            editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
                handleSaveRef.current();
            });

            monacoEditorRef.current = editor;
            setMonacoReady(true);
        });

        return () => {
            destroyed = true;
        };
    }, [editorMode, loading]);

    // ── Sync word wrap ─────────────────────────────────────────────
    useEffect(() => {
        if (monacoEditorRef.current) {
            monacoEditorRef.current.updateOptions({ wordWrap: wordWrap ? 'on' : 'off' });
        }
    }, [wordWrap]);

    // ── Save function ──────────────────────────────────────────────
    const handleSave = useCallback(async () => {
        if (saving || loading || pageData.editWriteLocked) return;
        const valueToSave = monacoEditorRef.current ? monacoEditorRef.current.getValue() : contentRef.current;
        setSaving(true);
        setStatus({ type: 'idle', message: '' });
        try {
            const response = await fetch(`/api/client/servers/${server.containerId}/files/write?path=${encodeURIComponent(filePath)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: valueToSave }),
                credentials: 'same-origin'
            });
            const payload = await response.json();
            if (!response.ok || payload.error) throw new Error(payload.error || 'Failed to save');
            setStatus({ type: 'success', message: 'Saved successfully.' });
            setIsUnsaved(false);
            setTimeout(() => setStatus({ type: 'idle', message: '' }), 3000);
        } catch (err) {
            setStatus({ type: 'error', message: err.message || 'Error saving file.' });
        } finally {
            setSaving(false);
        }
    }, [saving, loading, pageData.editWriteLocked, server.containerId, filePath]);

    const handleSaveRef = useRef(handleSave);
    handleSaveRef.current = handleSave;

    // ── File switch ────────────────────────────────────────────────
    const handleFileSwitch = (newPath) => {
        if (newPath === filePath) return;
        if (isUnsaved && !window.confirm('You have unsaved changes. Switch files anyway?')) return;
        window.location.href = `/server/${server.containerId}/files/edit?path=${encodeURIComponent(newPath)}`;
    };

    // ── Mode switch ────────────────────────────────────────────────
    const switchMode = (mode) => {
        if (mode === editorMode) return;
        if (monacoEditorRef.current && editorMode === 'monaco') {
            setContent(monacoEditorRef.current.getValue());
            monacoEditorRef.current.dispose();
            monacoEditorRef.current = null;
            setMonacoReady(false);
        }
        setEditorMode(mode);
    };

    // ── Beforeunload guard ─────────────────────────────────────────
    useEffect(() => {
        const handler = (e) => { if (isUnsaved) { e.preventDefault(); e.returnValue = ''; } };
        window.addEventListener('beforeunload', handler);
        return () => window.removeEventListener('beforeunload', handler);
    }, [isUnsaved]);

    // ── Keyboard shortcut for plain mode ───────────────────────────
    useEffect(() => {
        const handler = (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                handleSaveRef.current();
            }
        };
        window.addEventListener('keydown', handler);
        return () => window.removeEventListener('keydown', handler);
    }, []);

    const lineCount = content.split('\n').length;
    const charCount = content.length;

    return (
        <ReactAppShell pageData={pageData} subtitle={`Editing ${fileName}`}>
            {/* Full-bleed editor frame – no PageContentBlock padding */}
            <div className="flex flex-col bg-[#0d0f12] rounded-2xl border border-neutral-800 shadow-2xl overflow-hidden"
                style={{ height: 'calc(100vh - 140px)', minHeight: '520px' }}>

                {/* ── Toolbar ─────────────────────────────────────── */}
                <div className="bg-neutral-900/90 backdrop-blur-md px-4 py-2.5 border-b border-neutral-800 flex items-center justify-between shrink-0 gap-4 flex-wrap">
                    {/* Left */}
                    <div className="flex items-center gap-3 min-w-0">
                        <a href={`/server/${server.containerId}/files?path=${encodeURIComponent(parentPath)}`}
                            className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-neutral-500 hover:text-white transition-colors shrink-0">
                            <i className="bi bi-arrow-left"></i> Files
                        </a>
                        <div className="w-px h-4 bg-neutral-800 shrink-0"></div>
                        <div className="flex items-center gap-2 min-w-0">
                            <i className="bi bi-file-earmark-code text-neutral-500 shrink-0"></i>
                            <span className="text-sm font-bold text-neutral-200 truncate font-mono">{fileName}</span>
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-500 font-mono shrink-0">{language}</span>
                        </div>
                        {isUnsaved && (
                            <span className="flex items-center gap-1 text-[10px] font-black text-amber-500 uppercase tracking-widest shrink-0">
                                <span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse"></span> Unsaved
                            </span>
                        )}
                        {pageData.editWriteLocked && (
                            <span className="flex items-center gap-1 text-[10px] font-black text-red-400 uppercase tracking-widest shrink-0">
                                <i className="bi bi-lock-fill"></i> Read Only
                            </span>
                        )}
                    </div>

                    {/* Controls */}
                    <div className="flex items-center gap-2 shrink-0 flex-wrap">
                        {/* Mode switcher */}
                        <div className="flex items-center bg-neutral-950 border border-neutral-800 rounded-lg p-0.5 gap-0.5">
                            {['monaco', 'plain'].map(m => (
                                <button key={m} onClick={() => switchMode(m)}
                                    className={`px-3 py-1 rounded text-[10px] font-black uppercase tracking-widest transition-all ${editorMode === m ? 'bg-neutral-700 text-white' : 'text-neutral-500 hover:text-white'}`}>
                                    {m === 'monaco' ? 'Monaco' : 'Plain'}
                                </button>
                            ))}
                        </div>

                        <button onClick={() => setSidebarOpen(v => !v)}
                            className={`flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest px-3 py-1.5 rounded-lg border transition-all ${sidebarOpen ? 'border-primary-700/50 bg-primary-900/20 text-primary-400' : 'border-neutral-800 text-neutral-500 hover:text-white hover:border-neutral-700'}`}>
                            <i className={`bi ${sidebarOpen ? 'bi-layout-sidebar-inset' : 'bi-layout-sidebar'}`}></i> Tree
                        </button>

                        <button onClick={() => setWordWrap(v => !v)}
                            className={`flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest px-3 py-1.5 rounded-lg border transition-all ${wordWrap ? 'border-primary-700/50 bg-primary-900/20 text-primary-400' : 'border-neutral-800 text-neutral-500 hover:text-white hover:border-neutral-700'}`}>
                            <i className="bi bi-text-wrap"></i> Wrap
                        </button>

                        {status.message && (
                            <span className={`text-[10px] font-black uppercase tracking-widest px-3 py-1 rounded-full border ${status.type === 'error' ? 'text-red-400 border-red-900/30 bg-red-950/20' : 'text-green-400 border-green-900/30 bg-green-950/20'}`}>
                                {status.type === 'error' ? <i className="bi bi-exclamation-triangle me-1"></i> : <i className="bi bi-check-circle me-1"></i>}
                                {status.message}
                            </span>
                        )}

                        <button onClick={handleSave} disabled={saving || loading || Boolean(pageData.editWriteLocked)}
                            className={`flex items-center gap-2 px-5 py-1.5 rounded-lg text-[11px] font-black uppercase tracking-widest transition-all ${saving || loading || pageData.editWriteLocked ? 'bg-neutral-800 text-neutral-600 cursor-not-allowed' : 'bg-primary-600 hover:bg-primary-500 text-white shadow-lg shadow-primary-900/30'}`}>
                            {saving ? <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin"></div> : <i className="bi bi-cloud-arrow-up"></i>}
                            {saving ? 'Saving…' : 'Save'}
                        </button>
                    </div>
                </div>

                {/* ── Body ─────────────────────────────────────────── */}
                <div className="flex-1 flex overflow-hidden">

                    {/* File tree sidebar */}
                    {sidebarOpen && (
                        <div className="w-60 bg-[#0a0c0f] border-r border-neutral-800 flex flex-col shrink-0 overflow-hidden">
                            <div className="px-3 py-2.5 border-b border-neutral-800/50 flex items-center justify-between">
                                <span className="text-[9px] font-black text-neutral-500 uppercase tracking-widest">Explorer</span>
                                {rootLoading && <div className="w-2.5 h-2.5 border border-t-primary-500 border-neutral-700 rounded-full animate-spin"></div>}
                            </div>
                            <div className="flex-1 overflow-y-auto py-1.5 scrollbar-thin scrollbar-track-transparent scrollbar-thumb-neutral-800">
                                {rootFiles.map(file => (
                                    <FileTreeItem key={file.name} item={{ ...file, directory: '/' }}
                                        currentPath={filePath} onFileSwitch={handleFileSwitch}
                                        serverId={server.containerId} />
                                ))}
                                {rootFiles.length === 0 && !rootLoading && (
                                    <div className="p-4 text-center text-[10px] text-neutral-600 uppercase tracking-widest">No files</div>
                                )}
                            </div>
                        </div>
                    )}

                    {/* Monaco / Plain container */}
                    <div className="flex-1 relative overflow-hidden">
                        {/* Loading overlay */}
                        {loading && (
                            <div className="absolute inset-0 flex items-center justify-center bg-[#0d0f12] z-20">
                                <div className="flex flex-col items-center gap-4">
                                    <div className="w-12 h-12 border-4 border-neutral-800 border-t-primary-500 rounded-full animate-spin"></div>
                                    <span className="text-[10px] font-black text-neutral-500 uppercase tracking-widest">Loading Buffer…</span>
                                </div>
                            </div>
                        )}

                        {/* Monaco container */}
                        {editorMode === 'monaco' && !loading && (
                            <div ref={editorContainerRef} className="absolute inset-0" />
                        )}

                        {/* Plain textarea */}
                        {editorMode === 'plain' && !loading && (
                            <textarea
                                value={content}
                                onChange={(e) => { setContent(e.target.value); setIsUnsaved(true); }}
                                spellCheck={false}
                                disabled={Boolean(pageData.editWriteLocked)}
                                className="absolute inset-0 w-full h-full p-6 bg-[#0d0f12] text-neutral-300 font-mono text-sm leading-relaxed resize-none focus:outline-none"
                                style={{ tabSize: 4 }}
                                placeholder="File is empty..."
                            />
                        )}
                    </div>
                </div>

                {/* ── Status Bar ───────────────────────────────────── */}
                <div className="bg-neutral-900/50 px-5 py-1.5 border-t border-neutral-800 flex justify-between items-center text-[10px] font-mono text-neutral-600 shrink-0">
                    <div className="flex items-center gap-4">
                        <span>{language}</span>
                        <span>{charCount.toLocaleString()} chars</span>
                        <span>{lineCount.toLocaleString()} lines</span>
                        {editorMode === 'monaco' && monacoReady && <span>Ln {cursorInfo.line}, Col {cursorInfo.col}</span>}
                    </div>
                    <div className="flex items-center gap-3">
                        <span>UTF-8</span>
                        {editorMode === 'monaco' && <span className="text-primary-600">Monaco {isUnsaved ? '●' : '○'}</span>}
                        <span>Ctrl+S to save</span>
                    </div>
                </div>
            </div>
        </ReactAppShell>
    );
}

import { BrowserRouter } from 'react-router-dom';

export default ServerFileEditorPage;

if (root) {
    root.render(
        <BrowserRouter>
            <ServerFileEditorPage pageData={data} />
        </BrowserRouter>
    );
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
