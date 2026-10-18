import { useState } from "react";

export default function ActionCard({ actions, onDecide }) {
  const [busyId, setBusyId] = useState(null);
  const [error, setError] = useState("");
  const decide = async (action, decision) => {
    setBusyId(action.id); setError("");
    try { await onDecide(action.id, decision); }
    catch (cause) {
      setError(cause.status === 409 ? `${action.id} was already decided. Refresh the investigation to see its current status.` : cause.status === 404 ? `${action.id} was not found by the server.` : `Could not update ${action.id}: ${cause.message}`);
    } finally { setBusyId(null); }
  };
  return <section className="panel" aria-labelledby="actions-heading">
    <header className="panel-heading"><div><p className="eyebrow">HUMAN DECISION REQUIRED</p><h2 id="actions-heading">Actions</h2></div></header>
    {error && <p className="error-box" role="alert">{error}</p>}
    {!actions.length && <p className="empty">No proposed actions returned.</p>}
    <ul className="action-list">{actions.map((action) => <li key={action.id}>
      <div className="action-copy"><strong>{action.type}</strong><span>{action.status}</span><p>{action.payload?.rationale}</p><small>{action.id} · {action.case_id}</small></div>
      {action.status === "PENDING_APPROVAL" && <div className="action-buttons"><button type="button" disabled={busyId === action.id} onClick={() => decide(action, "approve")}>Approve</button><button className="reject-button" type="button" disabled={busyId === action.id} onClick={() => decide(action, "reject")}>Reject</button></div>}
    </li>)}</ul>
    <p className="muted">Actions require a human decision. No account is automatically blocked, suspended, or deactivated.</p>
  </section>;
}
