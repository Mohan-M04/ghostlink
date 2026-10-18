import { useCallback, useEffect, useRef, useState } from "react";
import { decideAction, getAlerts, investigate, useMock } from "./api/client.js";
import AlertList from "./components/AlertList.jsx";
import InvestigationPanel from "./components/InvestigationPanel.jsx";
import GraphView from "./components/GraphView.jsx";
import EvidenceList from "./components/EvidenceList.jsx";
import ResultPanel from "./components/ResultPanel.jsx";
import ActionCard from "./components/ActionCard.jsx";

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [alertLoading, setAlertLoading] = useState(true);
  const [alertError, setAlertError] = useState("");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [steps, setSteps] = useState([]);
  const [report, setReport] = useState(null);
  const [status, setStatus] = useState("empty");
  const [streamError, setStreamError] = useState("");
  const [selectedFinding, setSelectedFinding] = useState(null);
  const controller = useRef(null);
  const lastAlert = useRef(null);

  useEffect(() => {
    let active = true;
    getAlerts().then((items) => { if (active) setAlerts(items); }).catch((error) => { if (active) setAlertError(error.message); }).finally(() => { if (active) setAlertLoading(false); });
    return () => { active = false; controller.current?.abort(); };
  }, []);

  const runInvestigation = useCallback(async (alert, keepPartial = false) => {
    controller.current?.abort();
    const abortController = new AbortController();
    controller.current = abortController;
    lastAlert.current = alert;
    setSelectedAlert(alert);
    if (!keepPartial) { setSteps([]); setReport(null); setSelectedFinding(null); }
    setStreamError(""); setStatus("loading");
    let done = false;
    try {
      for await (const event of investigate(alert, abortController.signal)) {
        if (event.type === "step") setSteps((current) => [...current, event]);
        else if (event.type === "report") setReport(event.report);
        else if (event.type === "error") setStreamError(`${event.code}: ${event.message}`);
        else if (event.type === "done") {
          done = true;
          setStatus(event.status === "complete" ? "complete" : event.status === "incomplete" ? "incomplete" : "failed");
        }
      }
      if (!done) setStatus("disconnected");
    } catch (error) {
      if (error.name === "AbortError") return;
      setStreamError(error.message);
      setStatus(error.message.includes("Network request failed") ? "network-error" : "failed");
    }
  }, []);

  const cancel = () => { controller.current?.abort(); setStatus("cancelled"); };
  const retry = () => { if (lastAlert.current) runInvestigation(lastAlert.current, status === "disconnected"); };
  const handleDecision = async (actionId, decision) => {
    const updated = await decideAction(actionId, decision);
    setReport((current) => current && ({ ...current, actions: current.actions.map((action) => action.id === actionId ? { ...action, ...updated } : action) }));
  };
  const incomplete = status === "incomplete" || Boolean(report?.limits_hit?.length);

  return <main className="app-shell">
    <header className="topbar"><a className="brand" href="#" aria-label="GhostLink home"><span className="brand-mark">G</span><span>GHOSTLINK<small>INVESTIGATION WORKSPACE</small></span></a><div className="topbar-meta"><span className="connection"><i />{useMock ? "Mock mode" : "Backend mode"}</span><span className="simulated-tag">SIMULATED DATA</span></div></header>
    <section className="hero"><div><p className="eyebrow">GRAPH-BASED ACCOUNT INVESTIGATION</p><h1>Network signal review</h1><p>Trace relationships, inspect evidence, and route proposals to a human analyst.</p></div><p className="safety-note">Shared infrastructure alone is never proof of fraud.</p></section>
    {alertError && <div className="error-box" role="alert">Could not load alerts: {alertError}</div>}
    <div className="dashboard">
      <div className="column-left"><AlertList alerts={alerts} selectedId={selectedAlert?.id} activeId={status === "loading" ? selectedAlert?.id : null} onInvestigate={runInvestigation} loading={alertLoading} /><InvestigationPanel steps={steps} status={status} error={streamError} onRetry={retry} onCancel={cancel} /><ActionCard actions={report?.actions ?? []} onDecide={handleDecision} /></div>
      <div className="column-right"><GraphView graph={report?.graph} findings={report?.findings ?? []} selectedFinding={selectedFinding} onSelectFinding={setSelectedFinding} /><EvidenceList findings={report?.findings ?? []} evidence={report?.evidence ?? []} selectedFinding={selectedFinding} onSelectFinding={setSelectedFinding} /><ResultPanel report={report} incomplete={incomplete} /></div>
    </div>
    <footer>GhostLink · Synthetic data only · Scores are provisional prioritisation aids, not probabilities of guilt.</footer>
  </main>;
}
