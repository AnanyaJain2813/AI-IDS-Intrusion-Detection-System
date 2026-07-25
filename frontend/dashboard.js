// Point this at your Flask API. Defaults to local dev server.
const API = "http://127.0.0.1:5000";

let timelineChart, severityChart;

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

async function fetchJSON(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

function renderFeed(elId, events) {
  const el = document.getElementById(elId);
  if (!events || events.length === 0) {
    el.innerHTML = '<div class="empty">No events yet.</div>';
    return;
  }
  el.innerHTML = events.slice(0, 50).map(e => `
    <div class="row ${e.threat_level.toLowerCase()}">
      <div class="time">${fmtTime(e.ts)}</div>
      <div class="sev ${e.threat_level.toLowerCase()}">${e.threat_level}</div>
      <div>${e.message || `${e.category} — ${e.ip_address || ''}`}</div>
    </div>
  `).join("");
}

function renderTopIPs(rows) {
  const tbody = document.querySelector("#top-ips-table tbody");
  if (!rows || rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="color:var(--dim)">No data yet.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td>${r.ip_address}</td>
      <td>${r.event_count}</td>
      <td>${r.avg_score}</td>
      <td>${r.max_score}</td>
    </tr>
  `).join("");
}

function renderStats(stats) {
  document.getElementById("s-total").textContent = stats.total_logs;
  document.getElementById("s-anomalies").textContent = stats.total_anomalies;
  document.getElementById("s-alerts").textContent = stats.total_alerts;
  document.getElementById("s-ips").textContent = stats.suspicious_ips;
  document.getElementById("s-avg").textContent = stats.avg_threat_score;
  document.getElementById("s-max").textContent = stats.max_threat_score;

  const levels = stats.threat_levels;
  const data = [levels.LOW, levels.MEDIUM, levels.HIGH, levels.CRITICAL];
  if (severityChart) {
    severityChart.data.datasets[0].data = data;
    severityChart.update();
  } else {
    severityChart = new Chart(document.getElementById("chart-severity"), {
      type: "doughnut",
      data: {
        labels: ["Low", "Medium", "High", "Critical"],
        datasets: [{
          data,
          backgroundColor: ["#4fd6e8", "#f0b93d", "#f0563d", "#a855f7"],
          borderWidth: 0,
        }],
      },
      options: {
        plugins: { legend: { labels: { color: "#d8e0e6", font: { family: "IBM Plex Mono" } } } },
      },
    });
  }
}

function renderTimeline(rows) {
  const labels = rows.map(r => `${r.hour}:00`);
  const data = rows.map(r => r.count);
  if (timelineChart) {
    timelineChart.data.datasets[0].data = data;
    timelineChart.update();
  } else {
    timelineChart = new Chart(document.getElementById("chart-timeline"), {
      type: "bar",
      data: {
        labels,
        datasets: [{ data, backgroundColor: "#3ddc97", borderRadius: 3 }],
      },
      options: {
        scales: {
          x: { ticks: { color: "#6b7c88", font: { size: 10 } }, grid: { color: "#1e262d" } },
          y: { ticks: { color: "#6b7c88" }, grid: { color: "#1e262d" } },
        },
        plugins: { legend: { display: false } },
      },
    });
  }
}

async function refresh() {
  try {
    const [stats, timeline, topIps, logAlerts, networkAlerts] = await Promise.all([
      fetchJSON("/api/stats"),
      fetchJSON("/api/threats/timeline"),
      fetchJSON("/api/threats/top-ips"),
      fetchJSON("/api/alerts"),
      fetchJSON("/api/network/alerts"),
    ]);
    document.getElementById("api-status").textContent = "connected";
    document.getElementById("api-status").className = "api-status ok";

    renderStats(stats.data);
    renderTimeline(timeline.data);
    renderTopIPs(topIps.data);
    renderFeed("log-alerts-feed", logAlerts.data.filter(e => e.source !== "network"));
    renderFeed("network-alerts-feed", networkAlerts.data);
  } catch (e) {
    document.getElementById("api-status").textContent = "disconnected";
    document.getElementById("api-status").className = "api-status error";
    console.error(e);
  }
}

document.getElementById("analyse-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const form = new FormData(ev.target);
  const payload = {
    ip_address: form.get("ip_address"),
    username: form.get("username"),
    status: form.get("status"),
    failed_attempts: Number(form.get("failed_attempts")),
    port: Number(form.get("port")),
    hour: Number(form.get("hour")),
  };
  try {
    const res = await fetch(`${API}/api/analyse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    const box = document.getElementById("analyse-result");
    box.classList.add("visible");
    if (!data.success) {
      box.textContent = `Error: ${data.error}`;
    } else {
      box.innerHTML = `Threat score: <strong style="color:${data.result.threat_color}">${data.result.threat_score}</strong>
        &nbsp;·&nbsp; Level: <strong style="color:${data.result.threat_color}">${data.result.threat_level}</strong>
        &nbsp;·&nbsp; Anomaly: ${data.result.is_anomaly ? "Yes" : "No"}`;
    }
    refresh();
  } catch (e) {
    console.error(e);
  }
});

refresh();
setInterval(refresh, 5000);
