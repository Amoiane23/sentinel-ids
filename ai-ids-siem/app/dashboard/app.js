let API_BASE = localStorage.getItem("apiBase") || "http://127.0.0.1:8000";
let timelineChart, severityChart, classChart, confidenceChart;
let allRows = [];

const els = {
  apiBaseInput: document.getElementById("apiBaseInput"),
  apiStatusBadge: document.getElementById("apiStatusBadge"),
  modelInfoText: document.getElementById("modelInfoText"),
  totalPredictions: document.getElementById("totalPredictions"),
  attackCount: document.getElementById("attackCount"),
  benignCount: document.getElementById("benignCount"),
  riskScore: document.getElementById("riskScore"),
  avgConfidence: document.getElementById("avgConfidence"),
  avgLatency: document.getElementById("avgLatency"),
  predictionTableBody: document.getElementById("predictionTableBody"),
  eventLog: document.getElementById("eventLog"),
  topSuspiciousBody: document.getElementById("topSuspiciousBody"),
  ledgerSummary: document.getElementById("ledgerSummary"),
  suspiciousSummary: document.getElementById("suspiciousSummary"),
  exportSummary: document.getElementById("exportSummary"),
  thresholdValue: document.getElementById("thresholdValue"),
};

function setStatus(text, cls = "neutral") {
  els.apiStatusBadge.textContent = text;
  els.apiStatusBadge.className = `status-pill ${cls}`;
}

async function fetchJSON(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, options);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function loadHealth() {
  try {
    const data = await fetchJSON("/health");
    setStatus(data.status === "healthy" ? "Healthy" : "Error", data.status === "healthy" ? "good" : "bad");
  } catch {
    setStatus("Offline", "bad");
  }
}

async function loadModelInfo() {
  try {
    const data = await fetchJSON("/model-info");
    els.modelInfoText.textContent =
      `Model: ${data.model_type} | Features: ${data.feature_count} | Loaded: ${data.model_loaded}`;
  } catch {
    els.modelInfoText.textContent = "Unable to load model info.";
  }
}

async function loadSummary() {
  const s = await fetchJSON("/metrics/summary");
  els.totalPredictions.textContent = s.total_predictions;
  els.attackCount.textContent = s.attack_count;
  els.benignCount.textContent = s.benign_count;
  els.riskScore.textContent = `${s.risk_score}%`;
  els.avgConfidence.textContent = `${(s.avg_confidence * 100).toFixed(2)}%`;
  els.avgLatency.textContent = `${s.avg_latency} ms`;
}

function classifyByThreshold(row, threshold) {
  return row.attack_probability >= threshold ? "ATTACK" : "BENIGN";
}

function getFilteredRows() {
  const severity = document.getElementById("severityFilter").value;
  const type = document.getElementById("typeFilter").value;
  const source = document.getElementById("sourceFilter").value;
  const mins = document.getElementById("timeFilter").value;
  const threshold = parseFloat(document.getElementById("attackThreshold").value);

  const now = Date.now();

  return allRows.filter(r => {
    const predictedType = classifyByThreshold(r, threshold);

    if (severity !== "ALL" && r.severity !== severity) return false;
    if (type !== "ALL" && predictedType !== type) return false;
    if (source !== "ALL" && r.source !== source) return false;

    if (mins !== "ALL") {
      const diff = (now - new Date(r.timestamp).getTime()) / 60000;
      if (diff > parseInt(mins, 10)) return false;
    }
    return true;
  });
}

function renderTable(rows) {
  if (!rows.length) {
    els.predictionTableBody.innerHTML = `<tr><td colspan="7" class="empty-row">No predictions found for current filters.</td></tr>`;
    return;
  }

  els.predictionTableBody.innerHTML = rows.map(r => {
    const probs = JSON.parse(r.probabilities_json || "{}");
    const type = classifyByThreshold(r, parseFloat(document.getElementById("attackThreshold").value));
    return `
      <tr>
        <td>${r.timestamp}</td>
        <td>${r.source}</td>
        <td>${type}</td>
        <td>${r.severity}</td>
        <td>${(r.confidence * 100).toFixed(2)}%</td>
        <td>${r.latency_ms} ms</td>
        <td>B:${((probs.BENIGN || 0) * 100).toFixed(1)} / A:${((probs.ATTACK || 0) * 100).toFixed(1)}</td>
      </tr>
    `;
  }).join("");
}

function renderEvents(rows) {
  els.eventLog.innerHTML = rows.slice(0, 15).map(r => `
    <li>
      <strong>${r.attack_type}</strong> from <strong>${r.src_ip || "-"}</strong>
      to <strong>${r.dst_ip || "-"}</strong> | ${r.severity} | ${(r.attack_probability * 100).toFixed(1)}%
    </li>
  `).join("");
}

function renderSuspicious(rows) {
  const ranked = [...rows].sort((a, b) => b.attack_probability - a.attack_probability).slice(0, 10);
  els.suspiciousSummary.textContent = `${ranked.length} rows`;
  if (!ranked.length) {
    els.topSuspiciousBody.innerHTML = `<tr><td colspan="5" class="empty-row">No suspicious records available yet.</td></tr>`;
    return;
  }

  els.topSuspiciousBody.innerHTML = ranked.map(r => `
    <tr>
      <td>${r.timestamp}</td>
      <td>${r.source}</td>
      <td>${(r.attack_probability * 100).toFixed(2)}%</td>
      <td>${r.severity}</td>
      <td>${r.latency_ms} ms</td>
    </tr>
  `).join("");
}

function initCharts() {
  timelineChart = new Chart(document.getElementById("timelineChart"), {
    type: "line",
    data: { labels: [], datasets: [
      { label: "Attack", data: [], borderColor: "#ff5d73", tension: 0.3 },
      { label: "Benign", data: [], borderColor: "#25d3a2", tension: 0.3 }
    ] }
  });

  severityChart = new Chart(document.getElementById("severityChart"), {
    type: "doughnut",
    data: { labels: ["CRITICAL", "HIGH", "MEDIUM", "LOW"], datasets: [{ data: [0,0,0,0] }] }
  });

  classChart = new Chart(document.getElementById("classChart"), {
    type: "bar",
    data: { labels: ["BENIGN", "ATTACK"], datasets: [{ data: [0,0] }] }
  });

  confidenceChart = new Chart(document.getElementById("confidenceChart"), {
    type: "bar",
    data: { labels: ["0-20", "20-40", "40-60", "60-80", "80-100"], datasets: [{ data: [0,0,0,0,0] }] }
  });
}

function updateCharts(rows) {
  const threshold = parseFloat(document.getElementById("attackThreshold").value);
  const latest = rows.slice(0, 30).reverse();

  timelineChart.data.labels = latest.map((_, i) => `${i + 1}`);
  timelineChart.data.datasets[0].data = latest.map(r => classifyByThreshold(r, threshold) === "ATTACK" ? 1 : 0);
  timelineChart.data.datasets[1].data = latest.map(r => classifyByThreshold(r, threshold) === "BENIGN" ? 1 : 0);
  timelineChart.update();

  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  rows.forEach(r => { if (sevCounts[r.severity] !== undefined) sevCounts[r.severity]++; });
  severityChart.data.datasets[0].data = [sevCounts.CRITICAL, sevCounts.HIGH, sevCounts.MEDIUM, sevCounts.LOW];
  severityChart.update();

  let benign = 0, attack = 0;
  rows.forEach(r => classifyByThreshold(r, threshold) === "ATTACK" ? attack++ : benign++);
  classChart.data.datasets[0].data = [benign, attack];
  classChart.update();

  const bins = [0, 0, 0, 0, 0];
  rows.forEach(r => {
    const c = r.confidence * 100;
    if (c < 20) bins[0]++;
    else if (c < 40) bins[1]++;
    else if (c < 60) bins[2]++;
    else if (c < 80) bins[3]++;
    else bins[4]++;
  });
  confidenceChart.data.datasets[0].data = bins;
  confidenceChart.update();
}

function refreshViews() {
  const filtered = getFilteredRows();
  els.ledgerSummary.textContent = `${filtered.length} rows`;
  els.exportSummary.textContent = `${filtered.length} filtered rows`;
  renderTable(filtered);
  renderEvents(filtered);
  renderSuspicious(filtered);
  updateCharts(filtered);
}

async function loadAlerts() {
  allRows = await fetchJSON("/alerts?limit=500");
  refreshViews();
}

async function predictSingle() {
  const raw = document.getElementById("singleRowInput").value.trim();
  const arr = raw.split(",").map(x => parseFloat(x.trim())).filter(x => !Number.isNaN(x));
  await fetchJSON("/predict", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ features: arr, source: "MANUAL" })
  });
  await refreshAll();
}

async function predictBatch() {
  const raw = document.getElementById("batchInput").value.trim();
  let payload = JSON.parse(raw);
  if (Array.isArray(payload)) payload = { rows: payload, source: "BATCH" };
  await fetchJSON("/predict-batch", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });
  await refreshAll();
}

async function predictCsv() {
  const fileInput = document.getElementById("csvInput");
  if (!fileInput.files.length) return alert("Choose a CSV file first.");
  const fd = new FormData();
  fd.append("file", fileInput.files[0]);
  const res = await fetch(`${API_BASE}/predict-csv`, { method: "POST", body: fd });
  if (!res.ok) throw new Error("CSV upload failed");
  await refreshAll();
}

async function clearSessionData() {
  await fetchJSON("/alerts", { method: "DELETE" });
  await refreshAll();
}

function downloadFile(name, content, mime) {
  const blob = new Blob([content], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

function exportJson() {
  const rows = getFilteredRows();
  downloadFile("sentinel_filtered.json", JSON.stringify(rows, null, 2), "application/json");
}

function exportCsv() {
  const rows = getFilteredRows();
  if (!rows.length) return;
  const headers = Object.keys(rows[0]);
  const lines = [headers.join(",")];
  rows.forEach(r => {
    lines.push(headers.map(h => JSON.stringify(r[h] ?? "")).join(","));
  });
  downloadFile("sentinel_filtered.csv", lines.join("\n"), "text/csv");
}

async function refreshAll() {
  await loadHealth();
  await loadModelInfo();
  await loadSummary();
  await loadAlerts();
}

window.addEventListener("DOMContentLoaded", () => {
  els.apiBaseInput.value = API_BASE;
  initCharts();

  document.getElementById("saveApiBaseBtn").addEventListener("click", () => {
    API_BASE = document.getElementById("apiBaseInput").value.trim();
    localStorage.setItem("apiBase", API_BASE);
    refreshAll();
  });

  document.getElementById("healthBtn").addEventListener("click", loadHealth);
  document.getElementById("loadModelInfoBtn").addEventListener("click", loadModelInfo);
  document.getElementById("clearHistoryBtn").addEventListener("click", clearSessionData);
  document.getElementById("predictSingleBtn").addEventListener("click", predictSingle);
  document.getElementById("predictBatchBtn").addEventListener("click", predictBatch);
  document.getElementById("predictCsvBtn").addEventListener("click", predictCsv);
  document.getElementById("exportJsonBtn").addEventListener("click", exportJson);
  document.getElementById("exportCsvBtn").addEventListener("click", exportCsv);

  document.getElementById("loadMockRowBtn").addEventListener("click", () => {
    document.getElementById("singleRowInput").value = Array.from({length: 63}, (_, i) => (i % 7) * 0.13).join(", ");
  });

  ["severityFilter", "typeFilter", "timeFilter", "sourceFilter", "attackThreshold"].forEach(id => {
    document.getElementById(id).addEventListener("input", () => {
      const v = parseFloat(document.getElementById("attackThreshold").value);
      els.thresholdValue.textContent = `Attack >= ${(v * 100).toFixed(0)}%`;
      refreshViews();
    });
  });

  refreshAll();
  setInterval(refreshAll, 3000);
});