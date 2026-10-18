import { useEffect, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";

const colors = { Account: "#6caeff", IP: "#45d7ca", Device: "#c69aff", Transaction: "#ffb45f" };

export function transformGraph(graph = { nodes: [], links: [] }, finding = null) {
  const path = new Set(finding?.path ?? []);
  const highlighted = new Set();
  for (let index = 1; index < (finding?.path?.length ?? 0); index += 1) {
    highlighted.add([finding.path[index - 1], finding.path[index]].sort().join("|"));
  }
  return {
    nodes: (graph.nodes ?? []).map((node) => ({ ...node, highlighted: path.has(node.id), color: node.decoy ? "#737d85" : colors[node.type] ?? "#aab4bd" })),
    links: (graph.links ?? []).map((link) => {
      const source = typeof link.source === "object" ? link.source.id : link.source;
      const target = typeof link.target === "object" ? link.target.id : link.target;
      return { ...link, source, target, highlighted: highlighted.has([source, target].sort().join("|")) };
    })
  };
}

export default function GraphView({ graph, findings, selectedFinding, onSelectFinding }) {
  const [hoveredNode, setHoveredNode] = useState(null);
  const [graphWidth, setGraphWidth] = useState(() => Math.max(240, Math.min(760, window.innerWidth - 48)));
  const graphContainer = useRef(null);
  const selected = findings.find((finding) => finding.id === selectedFinding) ?? null;
  const data = transformGraph(graph, selected);
  useEffect(() => {
    if (!graphContainer.current || typeof ResizeObserver === "undefined") return undefined;
    const observer = new ResizeObserver(([entry]) => setGraphWidth(Math.max(280, Math.floor(entry.contentRect.width))));
    observer.observe(graphContainer.current);
    return () => observer.disconnect();
  }, []);
  return (
    <section className="panel" aria-labelledby="graph-heading">
      <header className="panel-heading"><div><p className="eyebrow">ENTITY RELATIONSHIPS</p><h2 id="graph-heading">Graph</h2></div></header>
      {findings.length > 0 && <label className="select-label">Highlight finding <select aria-label="Highlight finding" value={selectedFinding ?? ""} onChange={(event) => onSelectFinding(event.target.value || null)}><option value="">No path selected</option>{findings.map((finding) => <option value={finding.id} key={finding.id}>{finding.id} · {finding.signal_type}</option>)}</select></label>}
      {data.nodes.length ? <div className="graph-canvas" ref={graphContainer}><ForceGraph2D
        graphData={data} nodeId="id" width={graphWidth} height={340} backgroundColor="#111b23"
        linkColor={(link) => link.decoy ? "#68737c" : link.highlighted ? "#ffbf47" : "#52616c"}
        linkLineDash={(link) => link.decoy ? [5, 4] : null}
        linkWidth={(link) => link.highlighted ? 3 : 1}
        nodeColor={(node) => node.color} nodeRelSize={5}
        nodeCanvasObject={(node, ctx, scale) => {
          const label = node.label || node.id;
          const fontSize = Math.max(9, 12 / scale);
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.highlighted ? 7 : 5, 0, 2 * Math.PI);
          ctx.fillStyle = node.color;
          ctx.fill();
          if (node.decoy) {
            ctx.setLineDash([3, 2]);
            ctx.strokeStyle = "#c0c7cc";
            ctx.stroke();
            ctx.setLineDash([]);
          }
          ctx.font = `${fontSize}px sans-serif`;
          ctx.fillStyle = "#e6edf2";
          ctx.fillText(label, node.x + 8, node.y + 3);
        }}
        nodePointerAreaPaint={(node, color, ctx) => {
          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.arc(node.x, node.y, 8, 0, 2 * Math.PI);
          ctx.fill();
        }}
        onNodeHover={setHoveredNode}
      /></div> : <p className="empty">No graph entities returned.</p>}
      {hoveredNode && <p className="graph-detail" role="status"><strong>{hoveredNode.label || hoveredNode.id}:</strong> {hoveredNode.detail || "No additional detail returned."}</p>}
      <div className="legend" aria-label="Graph legend">{Object.entries(colors).map(([type, color]) => <span key={type}><i style={{ backgroundColor: color }} />{type}</span>)}<span><i className="legend-decoy" />Decoy (dashed)</span><span><i className="legend-path" />Evidence path</span></div>
      {data.nodes.length > 0 && <p className="muted graph-detail">Hover over an entity to inspect its returned detail. Decoys are rendered grey and dashed.</p>}
    </section>
  );
}
