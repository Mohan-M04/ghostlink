export default function InvestigationPanel({ steps, status, error, onRetry, onCancel }) {
  return (
    <section className="panel" aria-labelledby="live-heading">
      <header className="panel-heading"><div><p className="eyebrow">LIVE TRACE</p><h2 id="live-heading">Investigation</h2></div><span className={`status-pill status-${status}`}>{status}</span></header>
      {status === "loading" && <button className="quiet-button" type="button" onClick={onCancel}>Cancel investigation</button>}
      {status === "disconnected" && <div className="warning" role="alert"><strong>Connection lost.</strong> Partial steps are retained. <button type="button" onClick={onRetry}>Retry</button></div>}
      {error && status !== "disconnected" && <div className="error-box" role="alert">{error} {(status === "failed" || status === "network-error") && <button type="button" onClick={onRetry}>Retry</button>}</div>}
      {status === "empty" && <p className="empty">Choose an alert to begin an investigation.</p>}
      {steps.length === 0 && status === "loading" && <p className="muted" role="status">Connecting to investigation stream…</p>}
      <ol className="trace-list">
        {steps.map((step, index) => <li key={`${step.seq ?? index}-${index}`}><span className={`trace-kind kind-${step.kind}`}>{step.kind}</span><div><p>{step.message}</p><small>{step.tool ? `Tool: ${step.tool} · ` : ""}{step.ok === null || step.ok === undefined ? "" : step.ok ? "success" : "failed"}{step.evidence_ids?.length ? ` · Evidence ${step.evidence_ids.join(", ")}` : ""}</small></div></li>)}
      </ol>
    </section>
  );
}
