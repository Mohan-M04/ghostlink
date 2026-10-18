export default function EvidenceList({ findings, evidence, selectedFinding, onSelectFinding }) {
  if (!findings.length) return <section className="panel"><header className="panel-heading"><div><p className="eyebrow">PROVENANCE</p><h2>Evidence</h2></div></header><p className="empty">No findings returned.</p></section>;
  const byId = new Map(evidence.map((item) => [item.id, item]));
  return <section className="panel" aria-labelledby="evidence-heading">
    <header className="panel-heading"><div><p className="eyebrow">PROVENANCE</p><h2 id="evidence-heading">Evidence</h2></div></header>
    <div className="finding-list">{findings.map((finding) => <article key={finding.id} className={`finding ${selectedFinding === finding.id ? "finding-selected" : ""}`}>
      <button className="finding-select" type="button" aria-pressed={selectedFinding === finding.id} onClick={() => onSelectFinding(selectedFinding === finding.id ? null : finding.id)}><strong>{finding.id} · {finding.signal_type}</strong><span className={`tier tier-${finding.tier?.toLowerCase()}`}>{finding.tier}</span></button>
      <p>{finding.claim}</p>{finding.strength !== undefined && <p className="muted">Strength: {finding.strength}</p>}
      <ul className="evidence-items">{finding.evidence_ids.map((id) => {
        const item = byId.get(id);
        return <li key={id}><strong>{id}</strong>{item ? <><span className={`tier tier-${item.tier.toLowerCase()}`}>{item.tier}</span><span>Reliability {item.reliability}</span><span>{item.source}</span><span>{item.relationship}</span></> : <span className="muted">Evidence detail not returned.</span>}</li>;
      })}</ul>
      {finding.path?.length > 0 && <p className="path"><span>Supporting path:</span> {finding.path.join(" → ")}</p>}
    </article>)}</div>
  </section>;
}
