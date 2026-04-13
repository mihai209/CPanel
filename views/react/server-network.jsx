import React from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-network';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ServerNetworkPage({ pageData = data }) {
    const allocations = Array.isArray(pageData.allocations) ? pageData.allocations : [];
    const availableAllocations = Array.isArray(pageData.availableAllocations) ? pageData.availableAllocations : [];
    const summary = pageData.networkSummary || {};
    const canManage = Boolean(pageData.permissions && pageData.permissions.canManageNetwork);
    const actions = pageData.actions || {};

    return (
        <ReactAppShell pageData={pageData} subtitle="Network" pageClassName="react-network-page">
            <main className="react-surface-page">
                <section className="react-surface-header">
                    <div>
                        <p className="react-surface-eyebrow">Routing</p>
                        <h1>Network</h1>
                        <p className="react-surface-copy">Review assigned allocations, switch the primary binding, and assign additional ports through the existing server routes.</p>
                    </div>
                </section>

                {(pageData.success || pageData.error) ? (
                    <div className={`react-inline-alert ${pageData.error ? 'is-danger' : 'is-success'}`}>{pageData.error || pageData.success}</div>
                ) : null}

                <section className="react-network-grid">
                    <div className="react-ui-panel">
                        <div className="react-panel-heading">Allocation Summary</div>
                        <div className="react-stat-list">
                            <div className="react-stat-row"><span>Total assigned</span><strong>{allocations.length}</strong></div>
                            <div className="react-stat-row"><span>Token inventory</span><strong>{summary.allocationTokens || 0}</strong></div>
                            <div className="react-stat-row"><span>Assignable left</span><strong>{summary.remainingAssignable || 0}</strong></div>
                        </div>
                        {summary.inventoryAssignBlockedReason ? (
                            <div className="react-inline-alert is-warning">{summary.inventoryAssignBlockedReason}</div>
                        ) : null}
                    </div>

                    {canManage && availableAllocations.length ? (
                        <div className="react-ui-panel">
                            <div className="react-panel-heading">Assign Allocation</div>
                            <form method="POST" action={actions.assign} className="react-stack-form">
                                <label className="react-form-field">
                                    <span>Available port</span>
                                    <select name="allocationId" defaultValue={availableAllocations[0].id}>
                                        {availableAllocations.map((entry) => (
                                            <option key={entry.id} value={entry.id}>{`${entry.ip}:${entry.port}`}</option>
                                        ))}
                                    </select>
                                </label>
                                <button type="submit" className="react-ui-button is-primary">Assign Port</button>
                            </form>
                        </div>
                    ) : null}
                </section>

                <section className="react-ui-panel">
                    <div className="react-panel-heading">Assigned Allocations</div>
                    <div className="react-list-body">
                        {!allocations.length ? <div className="react-empty-state">No allocations are assigned to this server.</div> : null}
                        {allocations.map((entry) => (
                            <div key={entry.id} className="react-list-row is-stacked-mobile">
                                <div className="react-list-main">
                                    <div className={`react-pill-badge ${entry.isPrimary ? 'is-success' : 'is-muted'}`}>{entry.isPrimary ? 'Primary' : 'Secondary'}</div>
                                    <strong>{`${entry.ip}:${entry.port}`}</strong>
                                    <span>{entry.notes || 'No notes configured.'}</span>
                                </div>
                                {canManage ? (
                                    <div className="react-row-actions">
                                        {!entry.isPrimary ? (
                                            <form method="POST" action={`${actions.primaryBase}/${entry.id}/primary`}>
                                                <button type="submit" className="react-ui-button is-ghost is-small">Make Primary</button>
                                            </form>
                                        ) : null}
                                        {!entry.isPrimary ? (
                                            <form method="POST" action={`${actions.removeBase}/${entry.id}/delete`}>
                                                <button type="submit" className="react-ui-button is-danger is-small">Remove</button>
                                            </form>
                                        ) : null}
                                    </div>
                                ) : null}
                            </div>
                        ))}
                    </div>
                </section>
            </main>
        </ReactAppShell>
    );
}

export default ServerNetworkPage;

if (root) {
    root.render(<ServerNetworkPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
