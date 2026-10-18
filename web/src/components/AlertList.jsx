export default function AlertList({ alerts, selectedId, activeId, onInvestigate, loading }) {
  return (
    <section className="panel" aria-labelledby="alerts-heading">
      <header className="panel-heading"><div><p className="eyebrow">INCOMING SIGNALS</p><h2 id="alerts-heading">Alerts</h2></div><span className="count">{alerts.length} alerts</span></header>
      {loading && <p role="status" className="muted">Loading alerts…</p>}
      {!loading && alerts.length === 0 && <p className="empty">No alerts available.</p>}
      <ul className="alert-list">
        {alerts.map((alert) => <li key={alert.id} className={`alert-row ${selectedId === alert.id ? "selected" : ""}`}>
          <div className="alert-main"><span className={`severity severity-${alert.severity?.toLowerCase()}`}>{alert.severity ?? "unknown"}</span><strong>{alert.ip}</strong><span className="muted">{alert.source ?? alert.label ?? "Source not returned"}</span><time dateTime={alert.timestamp ?? undefined}>{alert.timestamp ? new Date(alert.timestamp).toLocaleString() : "Time not returned"}</time></div>
          <button type="button" aria-label={`${activeId === alert.id ? "Investigating" : "Investigate"} ${alert.ip}`} onClick={() => onInvestigate(alert)} disabled={loading || activeId === alert.id}>{activeId === alert.id ? "Investigating" : "Investigate"}</button>
        </li>)}
      </ul>
    </section>
  );
}
