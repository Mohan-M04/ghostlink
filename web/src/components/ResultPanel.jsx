export default function ResultPanel({ report, incomplete }) {
  if (!report) return <section className="panel"><header className="panel-heading"><div><p className="eyebrow">ASSESSMENT</p><h2>Results</h2></div></header><p className="empty">No investigation report returned.</p></section>;
  return <section className="panel results-panel" aria-labelledby="results-heading">
    <header className="panel-heading"><div><p className="eyebrow">ASSESSMENT · {report.case_id}</p><h2 id="results-heading">Results</h2></div><span className="simulated-tag">Simulated data</span></header>
    {incomplete && <div className="warning" role="alert">Incomplete investigation: limits were reached or the run did not complete.</div>}
    {report.limits_hit?.length > 0 && <div className="warning" role="alert">Investigation limits hit: {report.limits_hit.join(", ")}</div>}
    <div className="score-row"><strong className={`score score-${report.band}`}>{report.score}</strong><div><span className={`band band-${report.band}`}>{report.band?.replaceAll("_", " ")}</span><p className="disclaimer">{report.disclaimer}</p><strong className="not-probability">not a probability of guilt</strong></div></div>
    <h3>Recommended action</h3><p>{report.recommended_action}</p>
    <div className="result-columns">
      {[["Innocent explanations", report.innocent_explanations], ["Conflicts", report.conflicts], ["Limitations", report.limitations], ["Check next", report.check_next]].map(([title, values]) => <div key={title}><h3>{title}</h3>{values?.length ? <ul>{values.map((value, index) => <li key={`${title}-${index}`}>{value}</li>)}</ul> : <p className="muted">None returned.</p>}</div>)}
    </div>
    <h3>Guardrails</h3>{report.guardrails?.length ? <ul className="guardrail-list">{report.guardrails.map((item) => <li key={item.code}><span className={`guardrail-severity severity-${item.severity}`}>{item.severity}</span><strong>{item.code}</strong><span>{item.message}</span></li>)}</ul> : <p className="muted">No guardrail messages returned.</p>}
  </section>;
}
