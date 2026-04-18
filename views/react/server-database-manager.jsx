import React, { useState, useEffect, useRef } from 'react';
import ReactAppShell from './components/ReactAppShell';

export default function ServerDatabaseManagerPage({ pageData = {} }) {
    const { 
        server = {}, 
        entry = {}, 
        tables = [], 
        selectedTable = '', 
        tableColumns = [], 
        tableColumnMeta = [], 
        primaryKeyColumns = [], 
        tableRows = [], 
        tableRowCriteria = [],
        totalRows = 0,
        totalPages = 0,
        currentPage = 1,
        pageSize = 50,
        dbInspectError = null,
        queryPreview = null
    } = pageData;

    const [loading, setLoading] = useState(false);
    const [status, setStatus] = useState({ 
        type: pageData.error ? 'error' : (pageData.success ? 'success' : 'idle'), 
        message: pageData.error || pageData.success || '' 
    });

    const [modalMode, setModalMode] = useState(null); // 'insert' | 'update' | null
    const [currentRow, setCurrentRow] = useState(null);
    const [currentCriteria, setCurrentCriteria] = useState(null);
    const [formData, setFormData] = useState({});
    const [nullFields, setNullFields] = useState({});
    
    const sqlFileRef = useRef(null);
    const [importStatus, setImportStatus] = useState('');

    const baseManagerPath = `/server/${server.containerId}/database/${encodeURIComponent(entry.name || '')}`;

    const handleAction = async (url, method = 'POST', body = null, isJson = false) => {
        setLoading(true);
        setStatus({ type: 'idle', message: '' });
        try {
            const options = { method };
            if (body) {
                if (isJson) {
                    options.headers = { 'Content-Type': 'application/json' };
                    options.body = JSON.stringify(body);
                } else {
                    options.headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
                    options.body = new URLSearchParams(body);
                }
            }

            const res = await fetch(url, options);
            if (res.redirected) {
                window.location.href = res.url;
                return;
            }

            const data = await res.json();
            if (!res.ok || data.error) throw new Error(data.error || 'Operation failed');
            
            if (data.redirect) {
                window.location.href = data.redirect;
                return;
            }

            setStatus({ type: 'success', message: data.message || 'Operation successful.' });
            // For simple queries or actions that don't redirect, we might want to refresh state
            // but usually this page relies on full reloads for complex state.
        } catch (err) {
            setStatus({ type: 'error', message: err.message });
        } finally {
            setLoading(false);
        }
    };

    const openInsert = () => {
        setModalMode('insert');
        setFormData({});
        setNullFields({});
        setCurrentRow(null);
    };

    const openUpdate = (row, criteria) => {
        setModalMode('update');
        setCurrentRow(row);
        setCurrentCriteria(criteria);
        setFormData({ ...row });
        const nulls = {};
        Object.entries(row).forEach(([k, v]) => { if (v === null) nulls[k] = true; });
        setNullFields(nulls);
    };

    const handleFormSubmit = (e) => {
        e.preventDefault();
        const payload = { ...formData };
        Object.keys(nullFields).forEach(k => { if (nullFields[k]) payload[k] = null; });
        
        const url = modalMode === 'insert' ? `${baseManagerPath}/row/insert` : `${baseManagerPath}/row/update`;
        const body = {
            tableName: selectedTable,
            page: currentPage,
            rowValues: JSON.stringify(payload)
        };
        if (modalMode === 'update') body.rowCriteria = JSON.stringify(currentCriteria);
        
        handleAction(url, 'POST', body);
    };

    const handleImportSql = async () => {
        const file = sqlFileRef.current?.files?.[0];
        if (!file) {
            setImportStatus('Please select a file.');
            return;
        }
        setImportStatus('Importing...');
        setLoading(true);
        try {
            const text = await file.text();
            const res = await fetch(`${baseManagerPath}/import`, {
                method: 'POST',
                headers: { 'Content-Type': 'text/plain; charset=utf-8' },
                body: text
            });
            const data = await res.json();
            if (!res.ok || !data.success) throw new Error(data.error || 'Import failed');
            window.location.href = `${baseManagerPath}?success=${encodeURIComponent(data.message || 'Import successful')}`;
        } catch (err) {
            setImportStatus(`Error: ${err.message}`);
            setStatus({ type: 'error', message: err.message });
        } finally {
            setLoading(false);
        }
    };

    return (
        <ReactAppShell pageData={pageData} subtitle={`DB Manager: ${entry.name}`}>
            <div className="max-w-full space-y-6 pb-24 px-2">
                {/* ── Header Actions ─────────────────────────────────── */}
                <div className="flex flex-wrap gap-4 items-center justify-between bg-neutral-900/50 backdrop-blur-sm border border-neutral-800 rounded-2xl p-4 shadow-sm">
                    <div className="flex items-center gap-3">
                        <a href={`/server/${server.containerId}/databases`} className="w-10 h-10 rounded-xl bg-neutral-800 hover:bg-neutral-700 text-neutral-400 flex items-center justify-center transition-all">
                            <i className="bi bi-arrow-left"></i>
                        </a>
                        <div>
                            <h3 className="text-sm font-black text-neutral-200 uppercase tracking-widest">{entry.name}</h3>
                            <span className="text-[10px] text-neutral-500 font-bold uppercase tracking-tight">{entry.host?.name || 'Local Host'}</span>
                        </div>
                    </div>
                    <div className="flex gap-2">
                        <a href={`${baseManagerPath}/export.sql`} className="px-4 py-2 rounded-xl bg-green-500/10 hover:bg-green-500/20 text-green-400 text-[10px] font-black uppercase tracking-widest transition-all border border-green-500/20">
                            <i className="bi bi-download me-2"></i>Export SQL
                        </a>
                    </div>
                </div>

                {/* ── Errors / Alerts ────────────────────────────────── */}
                {(status.message || dbInspectError) && (
                    <div className={`p-4 rounded-xl border flex items-center gap-3 animate-in fade-in slide-in-from-top-2 duration-300 ${
                        (status.type === 'error' || dbInspectError) ? 'bg-red-500/10 border-red-500/20 text-red-400' : 'bg-green-500/10 border-green-500/20 text-green-400'
                    }`}>
                        <i className={`bi bi-exclamation-triangle-fill`}></i>
                        <span className="text-sm font-medium">{status.message || dbInspectError}</span>
                    </div>
                )}

                <div className="grid lg:grid-cols-4 gap-6 items-start">
                    {/* ── Table Navigator ──────────────────────────────── */}
                    <div className="lg:col-span-1 space-y-4">
                        <div className="bg-neutral-900/50 rounded-2xl border border-neutral-800 p-4">
                            <div className="flex items-center justify-between mb-4 px-1">
                                <h4 className="text-[10px] font-black text-neutral-600 uppercase tracking-widest">Tables</h4>
                                <span className="text-[10px] font-bold text-neutral-500 bg-neutral-800 px-2 py-0.5 rounded-full">{tables.length}</span>
                            </div>
                            <div className="space-y-1 max-h-[600px] overflow-y-auto pr-2 custom-scrollbar">
                                {tables.map(t => (
                                    <a 
                                        key={t} 
                                        href={`${baseManagerPath}?table=${encodeURIComponent(t)}`}
                                        className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-bold transition-all ${
                                            selectedTable === t ? 'bg-primary-500/10 text-primary-400 border border-primary-500/20 shadow-sm' : 'text-neutral-400 hover:bg-neutral-800 border border-transparent'
                                        }`}
                                    >
                                        <i className={`bi bi-table ${selectedTable === t ? 'text-primary-400' : 'text-neutral-600'}`}></i>
                                        <span className="truncate">{t}</span>
                                    </a>
                                ))}
                            </div>
                        </div>

                        <div className="bg-neutral-900/50 rounded-2xl border border-neutral-800 p-4 space-y-4">
                            <h4 className="text-[10px] font-black text-neutral-600 uppercase tracking-widest px-1">Import SQL</h4>
                            <div className="space-y-2">
                                <input ref={sqlFileRef} type="file" accept=".sql" className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-3 py-1.5 text-[10px] text-neutral-500 focus:outline-none" />
                                <button onClick={handleImportSql} disabled={loading} className="w-full py-2 rounded-xl bg-orange-500/10 hover:bg-orange-500/20 text-orange-400 text-[10px] font-black uppercase tracking-widest transition-all">
                                    <i className="bi bi-upload me-2"></i>Run Import
                                </button>
                                {importStatus && <div className="text-[9px] text-neutral-500 font-bold uppercase text-center">{importStatus}</div>}
                            </div>
                        </div>
                    </div>

                    {/* ── Content Area ────────────────────────────────── */}
                    <div className="lg:col-span-3 space-y-6">
                        {/* Table Preview */}
                        <div className="bg-neutral-900/50 rounded-2xl border border-neutral-800 overflow-hidden shadow-sm">
                            <div className="px-6 py-4 bg-neutral-900/30 border-b border-neutral-800 flex items-center justify-between flex-wrap gap-4">
                                <div className="flex items-center gap-3">
                                    <i className="bi bi-grid-3x3-gap-fill text-primary-400"></i>
                                    <h3 className="text-sm font-black text-neutral-200 uppercase tracking-widest">
                                        {selectedTable ? `Browsing: ${selectedTable}` : 'Select a table'}
                                    </h3>
                                </div>
                                {selectedTable && (
                                    <div className="flex items-center gap-4">
                                        <span className="text-[10px] font-black text-neutral-500 uppercase tracking-widest">{totalRows} total rows</span>
                                        <button onClick={openInsert} className="px-4 py-1.5 rounded-xl bg-primary-600 hover:bg-primary-500 text-white text-[10px] font-black uppercase tracking-widest transition-all shadow-lg shadow-primary-950/20">
                                            <i className="bi bi-plus-circle me-1"></i>Insert
                                        </button>
                                    </div>
                                )}
                            </div>

                            <div className="overflow-x-auto min-h-[300px]">
                                <table className="w-full text-left border-collapse min-w-max">
                                    <thead>
                                        <tr className="border-b border-neutral-800 bg-neutral-950/30">
                                            {tableColumns.map(col => (
                                                <th key={col} className="px-4 py-3 text-[10px] font-black text-neutral-600 uppercase tracking-widest">{col}</th>
                                            ))}
                                            {selectedTable && <th className="px-4 py-3 text-[10px] font-black text-neutral-600 uppercase tracking-widest text-right">Actions</th>}
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-neutral-800/50">
                                        {tableRows.length === 0 ? (
                                            <tr>
                                                <td colSpan={tableColumns.length + 1} className="px-4 py-12 text-center text-sm text-neutral-600 italic">
                                                    {selectedTable ? 'No rows found in this table.' : 'Pick a table from the sidebar to start inspecting data.'}
                                                </td>
                                            </tr>
                                        ) : (
                                            tableRows.map((row, idx) => (
                                                <tr key={idx} className="hover:bg-white/[0.02] transition-colors group">
                                                    {tableColumns.map(col => (
                                                        <td key={col} className="px-4 py-3 text-xs text-neutral-400 font-mono">
                                                            {row[col] === null ? <span className="text-neutral-700 italic">NULL</span> : String(row[col])}
                                                        </td>
                                                    ))}
                                                    <td className="px-4 py-3 text-right">
                                                        <div className="flex justify-end gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
                                                            <button 
                                                                onClick={() => openUpdate(row, tableRowCriteria[idx])}
                                                                className="w-7 h-7 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center hover:bg-blue-500/20 transition-all"
                                                            >
                                                                <i className="bi bi-pencil-square"></i>
                                                            </button>
                                                            <button 
                                                                onClick={() => { if(confirm('Delete row?')) handleAction(`${baseManagerPath}/row/delete`, 'POST', { tableName: selectedTable, rowCriteria: JSON.stringify(tableRowCriteria[idx]), page: currentPage }); }}
                                                                className="w-7 h-7 rounded-lg bg-red-500/10 border border-red-500/20 text-red-500 flex items-center justify-center hover:bg-red-500/20 transition-all"
                                                            >
                                                                <i className="bi bi-trash"></i>
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            ))
                                        )}
                                    </tbody>
                                </table>
                            </div>

                            {/* Pagination */}
                            {totalPages > 1 && (
                                <div className="px-6 py-4 bg-neutral-950/30 border-t border-neutral-800 flex items-center justify-between">
                                    <span className="text-[10px] font-black text-neutral-600 uppercase tracking-widest">Page {currentPage} of {totalPages}</span>
                                    <div className="flex gap-1">
                                        <a 
                                            href={currentPage > 1 ? `${baseManagerPath}?table=${encodeURIComponent(selectedTable)}&page=${currentPage - 1}` : '#'}
                                            className={`w-8 h-8 rounded-lg border border-neutral-800 flex items-center justify-center transition-all ${currentPage > 1 ? 'hover:bg-neutral-800 text-neutral-400' : 'opacity-30 pointer-events-none'}`}
                                        >
                                            <i className="bi bi-chevron-left"></i>
                                        </a>
                                        <a 
                                            href={currentPage < totalPages ? `${baseManagerPath}?table=${encodeURIComponent(selectedTable)}&page=${currentPage + 1}` : '#'}
                                            className={`w-8 h-8 rounded-lg border border-neutral-800 flex items-center justify-center transition-all ${currentPage < totalPages ? 'hover:bg-neutral-800 text-neutral-400' : 'opacity-30 pointer-events-none'}`}
                                        >
                                            <i className="bi bi-chevron-right"></i>
                                        </a>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* SQL Console */}
                        <div className="bg-neutral-900/50 rounded-2xl border border-neutral-800 p-6 flex flex-col gap-4 shadow-sm">
                            <div className="flex items-center justify-between px-1">
                                <div className="flex items-center gap-3">
                                    <i className="bi bi-terminal-fill text-blue-400"></i>
                                    <h4 className="text-[10px] font-black text-neutral-200 uppercase tracking-widest">SQL Console</h4>
                                </div>
                                <span className="text-[10px] text-neutral-600 font-bold uppercase">Direct Access</span>
                            </div>
                            <form 
                                onSubmit={(e) => {
                                    e.preventDefault();
                                    handleAction(`${baseManagerPath}/query`, 'POST', { sqlQuery: e.target.sqlQuery.value });
                                }}
                                className="space-y-3"
                            >
                                <textarea 
                                    name="sqlQuery"
                                    rows="5"
                                    className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-3 text-xs font-mono text-neutral-300 focus:outline-none focus:border-blue-500/50 min-h-[120px]"
                                    placeholder="SELECT * FROM table_name LIMIT 10;"
                                ></textarea>
                                <div className="flex justify-end">
                                    <button type="submit" disabled={loading} className="px-8 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-[10px] font-black uppercase tracking-widest transition-all shadow-lg shadow-blue-950/20">
                                        Execute Query
                                    </button>
                                </div>
                            </form>

                            {/* Query Result Preview */}
                            {queryPreview && (
                                <div className="mt-4 p-4 bg-neutral-950/50 border border-neutral-800 rounded-xl space-y-4">
                                    <div className="flex items-center justify-between text-[10px] font-black uppercase tracking-tight">
                                        <span className="text-neutral-500">Query Executed at {new Date(queryPreview.executedAt).toLocaleTimeString()}</span>
                                        <span className={queryPreview.success ? 'text-green-500' : 'text-red-500'}>{queryPreview.message || 'Complete'}</span>
                                    </div>
                                    <code className="block bg-neutral-950 p-3 rounded-lg text-[11px] text-blue-400 font-mono mb-2 border border-neutral-800/50 whitespace-pre-wrap">
                                        {queryPreview.query}
                                    </code>
                                    {queryPreview.rows && queryPreview.rows.length > 0 && (
                                        <div className="overflow-x-auto border border-neutral-800/50 rounded-lg">
                                            <table className="w-full text-left text-[10px] border-collapse">
                                                <thead className="bg-neutral-900">
                                                    <tr>
                                                        {(queryPreview.columns || []).map(c => <th key={c} className="px-3 py-2 text-neutral-600 uppercase font-black">{c}</th>)}
                                                    </tr>
                                                </thead>
                                                <tbody className="divide-y divide-neutral-800">
                                                    {queryPreview.rows.map((r, i) => (
                                                        <tr key={i}>
                                                            {(queryPreview.columns || []).map(c => <td key={c} className="px-3 py-1.5 font-mono text-neutral-400">{r[c] === null ? 'NULL' : String(r[c])}</td>)}
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            {/* ── Row CRUD Modal ─────────────────────────────────── */}
            {modalMode && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-neutral-950/80 backdrop-blur-sm p-4">
                    <div className="bg-neutral-900 border border-neutral-800 rounded-2xl w-full max-w-4xl shadow-2xl animate-in fade-in zoom-in duration-200">
                        <div className="px-6 py-4 border-b border-neutral-800 flex items-center justify-between">
                            <h3 className="text-sm font-black text-neutral-200 uppercase tracking-widest">
                                {modalMode === 'insert' ? `Insert Into ${selectedTable}` : `Update Row in ${selectedTable}`}
                            </h3>
                            <button onClick={() => setModalMode(null)} className="text-neutral-500 hover:text-white transition-colors"><i className="bi bi-x-lg"></i></button>
                        </div>
                        <form onSubmit={handleFormSubmit}>
                            <div className="p-6 max-h-[70vh] overflow-y-auto space-y-4 custom-scrollbar">
                                {tableColumnMeta.map((col) => (
                                    <div key={col.name} className="grid grid-cols-1 md:grid-cols-12 gap-4 items-center p-3 rounded-xl bg-neutral-950/30 border border-neutral-800/50">
                                        <div className="md:col-span-4 flex flex-col">
                                            <div className="flex items-center gap-2">
                                                <span className="text-xs font-bold text-neutral-300 font-mono">{col.name}</span>
                                                {col.isPrimary && <span className="px-1.5 py-0.5 rounded bg-primary-500/20 text-primary-400 text-[8px] font-black border border-primary-500/20">PK</span>}
                                                {col.isAutoIncrement && <span className="px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-500 text-[8px] font-black">AUTO</span>}
                                            </div>
                                            <span className="text-[10px] text-neutral-600 font-bold uppercase tracking-tight">{col.dataType || col.columnType}</span>
                                        </div>
                                        <div className="md:col-span-6">
                                            <input 
                                                type="text"
                                                disabled={nullFields[col.name]}
                                                value={formData[col.name] || ''}
                                                onChange={e => setFormData({...formData, [col.name]: e.target.value})}
                                                placeholder={col.defaultValue || ''}
                                                className={`w-full bg-neutral-950 border border-neutral-800 rounded-xl px-4 py-2 text-xs font-mono text-neutral-300 focus:outline-none focus:border-primary-500/50 ${nullFields[col.name] ? 'opacity-30 cursor-not-allowed' : ''}`}
                                            />
                                        </div>
                                        <div className="md:col-span-2 flex justify-end">
                                            <label className="flex items-center gap-2 cursor-pointer select-none">
                                                <input 
                                                    type="checkbox" 
                                                    checked={!!nullFields[col.name]} 
                                                    onChange={e => setNullFields({...nullFields, [col.name]: e.target.checked})}
                                                    className="w-3 h-3 rounded bg-neutral-950 border-neutral-800 text-primary-500 focus:ring-0"
                                                />
                                                <span className="text-[10px] font-black text-neutral-600 uppercase tracking-widest">NULL</span>
                                            </label>
                                        </div>
                                    </div>
                                ))}
                            </div>
                            <div className="px-6 py-4 border-t border-neutral-800 flex justify-end gap-3">
                                <button type="button" onClick={() => setModalMode(null)} className="px-6 py-2 rounded-xl text-neutral-500 text-xs font-black uppercase tracking-widest hover:bg-neutral-800 transition-all">Cancel</button>
                                <button type="submit" disabled={loading} className="px-8 py-2 rounded-xl bg-primary-600 hover:bg-primary-500 text-white text-xs font-black uppercase tracking-widest transition-all">
                                    {modalMode === 'insert' ? 'Insert Row' : 'Save Changes'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            <style dangerouslySetInnerHTML={{ __html: `
                .custom-scrollbar::-webkit-scrollbar { width: 6px; }
                .custom-scrollbar::-webkit-scrollbar-track { background: rgba(0,0,0,0.1); }
                .custom-scrollbar::-webkit-scrollbar-thumb { background: #2d2d35; border-radius: 10px; }
                .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #3b82f6; }
            `}} />
        </ReactAppShell>
    );
}
