import React, { useState, useEffect, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-file-editor';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function FileTreeItem({ item, currentPath, onFileSwitch, serverId, depth = 0 }) {
    const [isExpanded, setIsExpanded] = useState(false);
    const [children, setChildren] = useState([]);
    const [loading, setLoading] = useState(false);
    
    const fullPath = (item.directory === '/' ? '' : item.directory) + '/' + item.name;
    const isActive = fullPath === currentPath;

    const toggleExpand = async (e) => {
        e.stopPropagation();
        if (!item.isDirectory) {
            onFileSwitch(fullPath);
            return;
        }

        const nextState = !isExpanded;
        setIsExpanded(nextState);

        if (nextState && children.length === 0) {
            setLoading(true);
            try {
                const res = await fetch(`/api/client/servers/${serverId}/files/list?path=${encodeURIComponent(fullPath)}`, {
                    headers: { 'Accept': 'application/json' },
                    credentials: 'same-origin'
                });
                const payload = await res.json();
                if (payload.files) {
                    setChildren(payload.files.sort((a, b) => {
                        if (a.isDirectory && !b.isDirectory) return -1;
                        if (!a.isDirectory && b.isDirectory) return 1;
                        return a.name.localeCompare(b.name);
                    }));
                }
            } catch (err) {
                console.error('Failed to load subfolder:', err);
            } finally {
                setLoading(false);
            }
        }
    };

    return (
        <div className="select-none">
            <div 
                onClick={toggleExpand}
                style={{ paddingLeft: `${(depth * 12) + 12}px` }}
                className={`flex items-center gap-2 py-1.5 cursor-pointer rounded-lg transition-colors group ${isActive ? 'bg-primary-900/20 text-primary-300' : 'hover:bg-neutral-800/50 text-neutral-400 hover:text-neutral-200'}`}
            >
                <i className={`bi ${item.isDirectory ? (isExpanded ? 'bi-chevron-down text-[10px]' : 'bi-chevron-right text-[10px]') : 'bi-file-earmark-text text-neutral-600'}`}></i>
                <i className={`bi ${item.isDirectory ? (isExpanded ? 'bi-folder2-open text-amber-500' : 'bi-folder-fill text-amber-600/80') : 'bi-file-earmark-text'}`}></i>
                <span className={`text-[11px] truncate ${isActive ? 'font-bold' : 'font-medium'}`}>
                    {item.name}
                </span>
                {loading && <div className="w-2 h-2 border border-neutral-700 border-t-primary-500 rounded-full animate-spin ml-auto mr-2"></div>}
            </div>
            
            {item.isDirectory && isExpanded && (
                <div className="mt-0.5">
                    {children.map(child => (
                        <FileTreeItem 
                            key={`${fullPath}/${child.name}`} 
                            item={{ ...child, directory: fullPath }} 
                            currentPath={currentPath}
                            onFileSwitch={onFileSwitch}
                            serverId={serverId}
                            depth={depth + 1}
                        />
                    ))}
                    {children.length === 0 && !loading && (
                        <div style={{ paddingLeft: `${((depth + 1) * 12) + 28}px` }} className="text-[10px] text-neutral-600 italic py-1">
                            (empty)
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export function ServerFileEditorPage({ pageData = data }) {
    const server = pageData.server || {};
    const urlParams = new URLSearchParams(window.location.search);
    const filePath = urlParams.get('path') || '/';
    const fileName = filePath.split('/').pop();

    const [content, setContent] = useState('');
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [status, setStatus] = useState({ type: 'idle', message: '' });
    const [isUnsaved, setIsUnsaved] = useState(false);

    const [rootFiles, setRootFiles] = useState([]);
    const [rootLoading, setRootLoading] = useState(false);
    const [sidebarOpen, setSidebarOpen] = useState(true);

    const parentPath = pageData.parentPath || filePath.split('/').slice(0, -1).join('/') || '/';

    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setStatus({ type: 'idle', message: '' });

        fetch(`/api/client/servers/${server.containerId}/files/content?path=${encodeURIComponent(filePath)}`, {
            headers: { 'Accept': 'application/json' },
            credentials: 'same-origin'
        })
        .then(res => res.json())
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

        // Load root files for the tree
        setRootLoading(true);
        fetch(`/api/client/servers/${server.containerId}/files/list?path=/`, {
            headers: { 'Accept': 'application/json' },
            credentials: 'same-origin'
        })
        .then(res => res.json())
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
        .catch(() => {
            if (!cancelled) setRootLoading(false);
        });

        return () => { cancelled = true; };
    }, [server.containerId, filePath]);

    const handleSave = async () => {
        if (saving || loading || pageData.editWriteLocked) return;
        setSaving(true);
        setStatus({ type: 'idle', message: '' });

        try {
            const response = await fetch(`/api/client/servers/${server.containerId}/files/write?path=${encodeURIComponent(filePath)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content }),
                credentials: 'same-origin'
            });
            const payload = await response.json();
            if (!response.ok || payload.error) throw new Error(payload.error || 'Failed to save');
            
            setStatus({ type: 'success', message: 'File saved successfully.' });
            setIsUnsaved(false);
            setTimeout(() => setStatus({ type: 'idle', message: '' }), 3000);
        } catch (err) {
            setStatus({ type: 'error', message: err.message || 'Error saving file.' });
        } finally {
            setSaving(false);
        }
    };

    const handleFileSwitch = (newPath) => {
        if (newPath === filePath) return;
        if (isUnsaved) {
            if (!window.confirm('You have unsaved changes. Are you sure you want to switch files?')) {
                return;
            }
        }
        window.location.href = `/server/${server.containerId}/files/edit?path=${encodeURIComponent(newPath)}`;
    };

    // Prevent accidental navigation
    useEffect(() => {
        const handler = (e) => {
            if (isUnsaved) {
                e.preventDefault();
                e.returnValue = '';
            }
        };
        window.addEventListener('beforeunload', handler);
        return () => window.removeEventListener('beforeunload', handler);
    }, [isUnsaved]);

    return (
        <ReactAppShell pageData={pageData} subtitle="File Editor">
            <PageContentBlock 
                title={fileName || 'Editor'} 
                description={`Editing: ${filePath}`}
                eyebrow="File System"
            >
                <div className="flex flex-col h-[calc(100vh-280px)] min-h-[500px] bg-neutral-950 border border-neutral-800 rounded-2xl overflow-hidden shadow-2xl">
                    
                    {/* Editor Toolbar */}
                    <div className="bg-neutral-900/80 backdrop-blur-md px-6 py-3 border-b border-neutral-800 flex items-center justify-between shrink-0">
                        <div className="flex items-center gap-4">
                            <a 
                                href={`/server/${server.containerId}/files?path=${encodeURIComponent(parentPath)}`}
                                className="text-neutral-500 hover:text-neutral-100 transition-colors flex items-center gap-2 text-xs font-bold uppercase tracking-widest"
                            >
                                <i className="bi bi-arrow-left"></i> Back
                            </a>
                            <div className="h-4 w-px bg-neutral-800"></div>
                            
                            <button 
                                onClick={() => setSidebarOpen(!sidebarOpen)}
                                className={`flex items-center gap-2 text-[10px] font-black uppercase tracking-widest transition-colors ${sidebarOpen ? 'text-primary-400' : 'text-neutral-500 hover:text-neutral-300'}`}
                            >
                                <i className={`bi ${sidebarOpen ? 'bi-layout-sidebar-inset' : 'bi-layout-sidebar'}`}></i>
                                {sidebarOpen ? 'Hide Tree' : 'Show Tree'}
                            </button>

                            <div className="h-4 w-px bg-neutral-800"></div>
                            <div className="flex items-center gap-2">
                                <span className={`w-2 h-2 rounded-full ${isUnsaved ? 'bg-amber-500 animate-pulse' : 'bg-green-500'}`}></span>
                                <span className="text-[10px] font-black text-neutral-400 uppercase tracking-[0.2em]">
                                    {isUnsaved ? 'Unsaved Changes' : 'Synced'}
                                </span>
                            </div>
                        </div>

                        <div className="flex items-center gap-4">
                            {status.message && (
                                <div className={`text-[10px] font-bold uppercase tracking-widest px-3 py-1 rounded-full border ${status.type === 'error' ? 'text-red-400 border-red-900/30 bg-red-950/20' : 'text-green-400 border-green-900/30 bg-green-950/20'}`}>
                                    {status.message}
                                </div>
                            )}

                            <button 
                                onClick={handleSave}
                                disabled={saving || loading || pageData.editWriteLocked}
                                className={`flex items-center gap-2 px-6 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${saving || loading || pageData.editWriteLocked ? 'bg-neutral-800 text-neutral-600' : 'bg-primary-600 hover:bg-primary-500 text-white shadow-lg shadow-primary-900/20'}`}
                            >
                                {saving ? (
                                    <>
                                        <div className="w-3 h-3 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                                        Saving...
                                    </>
                                ) : (
                                    <>
                                        <i className="bi bi-cloud-arrow-up"></i>
                                        Save File
                                    </>
                                )}
                            </button>
                        </div>
                    </div>

                    <div className="flex-1 flex overflow-hidden">
                        {/* Recursive File Tree Sidebar */}
                        {sidebarOpen && (
                            <div className="w-64 bg-neutral-900/30 border-r border-neutral-800 flex flex-col overflow-hidden shrink-0">
                                <div className="p-4 border-b border-neutral-800/50 flex items-center justify-between bg-neutral-900/20">
                                    <span className="text-[10px] font-black text-neutral-400 uppercase tracking-widest">Root Filesystem</span>
                                    {rootLoading && <div className="w-3 h-3 border border-neutral-700 border-t-primary-500 rounded-full animate-spin"></div>}
                                </div>
                                <div className="flex-1 overflow-y-auto p-2 custom-scrollbar bg-neutral-900/10">
                                    <div className="space-y-0.5">
                                        {rootFiles.map(file => (
                                            <FileTreeItem 
                                                key={file.name} 
                                                item={{ ...file, directory: '/' }} 
                                                currentPath={filePath}
                                                onFileSwitch={handleFileSwitch}
                                                serverId={server.containerId}
                                            />
                                        ))}
                                        {rootFiles.length === 0 && !rootLoading && (
                                            <div className="p-8 text-center text-[10px] text-neutral-600 uppercase tracking-widest leading-loose">
                                                No files found <br/> in root directory
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Editor Area */}
                        <div className="flex-1 relative">
                            {loading ? (
                                <div className="absolute inset-0 flex items-center justify-center bg-neutral-950 z-20">
                                    <div className="flex flex-col items-center gap-4">
                                        <div className="w-12 h-12 border-4 border-neutral-800 border-t-primary-500 rounded-full animate-spin"></div>
                                        <span className="text-xs font-bold text-neutral-500 uppercase tracking-widest">Loading Buffer...</span>
                                    </div>
                                </div>
                            ) : null}

                            <textarea 
                                value={content}
                                onChange={(e) => {
                                    setContent(e.target.value);
                                    setIsUnsaved(true);
                                }}
                                spellCheck={false}
                                className="w-full h-full p-8 bg-neutral-950 text-neutral-300 font-mono text-sm resize-none focus:outline-none focus:ring-1 focus:ring-primary-500/20"
                                placeholder="File is empty..."
                                style={{ 
                                    tabSize: 4,
                                    lineHeight: '1.6',
                                    background: 'linear-gradient(to bottom, #0a0c0e, #0a0c0e) padding-box, linear-gradient(to bottom, #0a0c0e, #0f1114) border-box'
                                }}
                            />
                        </div>
                    </div>

                    {/* Footer Info */}
                    <div className="bg-neutral-900/50 px-6 py-2 border-t border-neutral-800 flex justify-between items-center text-[10px] font-mono text-neutral-600 shrink-0">
                        <div>
                            UTF-8 · {content.length} chars · {content.split('\n').length} lines
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="flex items-center gap-1"><i className="bi bi-cursor"></i> Cursor Tracking Active</span>
                            {pageData.editWriteLocked && <span className="text-red-500 font-bold uppercase"><i className="bi bi-lock-fill"></i> Read Only Mode</span>}
                        </div>
                    </div>
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerFileEditorPage;

if (root) {
    root.render(<ServerFileEditorPage pageData={data} />);
}
