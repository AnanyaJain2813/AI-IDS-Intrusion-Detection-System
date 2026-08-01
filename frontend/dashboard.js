// Point this at your Flask API. Defaults to local dev server.
const API = "http://127.0.0.1:5000";

let timelineChart, severityChart, entityChart;
let activeEntityIp = null;

function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

function getAuthHeaders() {
  const token = localStorage.getItem("sentry_api_key");
  const headers = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function fetchJSON(path) {
  const headers = getAuthHeaders();
  const res = await fetch(`${API}${path}`, { headers });
  if (res.status === 401) {
    handleUnauthorized();
  }
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

let currentAuthTab = "login";

function switchAuthTab(tab) {
  currentAuthTab = tab;
  document.getElementById("tab-login").classList.toggle("active", tab === "login");
  document.getElementById("tab-register").classList.toggle("active", tab === "register");
  document.getElementById("auth-submit-btn").textContent = tab === "login" ? "Login" : "Register";
  document.getElementById("auth-error").textContent = "";
  document.getElementById("api-key-display").style.display = "none";
}

function handleUnauthorized() {
  localStorage.removeItem("sentry_api_key");
  localStorage.removeItem("sentry_username");
  document.getElementById("auth-container").style.display = "flex";
  document.querySelector("main").style.display = "none";
  document.getElementById("user-profile").style.display = "none";
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  const usernameInput = document.getElementById("auth-username");
  const passwordInput = document.getElementById("auth-password");
  const errorEl = document.getElementById("auth-error");
  const keyDisplayEl = document.getElementById("api-key-display");

  errorEl.textContent = "";
  keyDisplayEl.style.display = "none";

  const username = usernameInput.value;
  const password = passwordInput.value;

  const url = currentAuthTab === "login" ? "/api/login" : "/api/register";

  try {
    const res = await fetch(`${API}${url}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (!data.success) {
      errorEl.textContent = data.error || "Authentication failed";
      return;
    }

    localStorage.setItem("sentry_api_key", data.api_key);
    localStorage.setItem("sentry_username", data.username);

    if (currentAuthTab === "register") {
      keyDisplayEl.innerHTML = `🔑 <strong>Registration Successful!</strong><br><br>Copy your Agent API Key:<br><code style="font-weight:bold; color:var(--low); font-size:13px; display:block; margin: 8px 0;">${data.api_key}</code>Use this when running the capture/monitor.py script!<br><br><button onclick="checkLoginState()" style="padding:4px 8px; font-family:inherit; background:var(--low); color:var(--bg); border:none; cursor:pointer;">Continue to Dashboard</button>`;
      keyDisplayEl.style.display = "block";
      usernameInput.value = "";
      passwordInput.value = "";
    } else {
      usernameInput.value = "";
      passwordInput.value = "";
      checkLoginState();
    }
  } catch (err) {
    errorEl.textContent = "Could not connect to the Sentry server.";
  }
}

function checkLoginState() {
  const token = localStorage.getItem("sentry_api_key");
  const username = localStorage.getItem("sentry_username");

  if (token) {
    document.getElementById("auth-container").style.display = "none";
    document.querySelector("main").style.display = "flex";
    document.getElementById("user-profile").style.display = "flex";
    document.getElementById("display-username").textContent = `USER: ${username}`;
    refresh();
  } else {
    handleUnauthorized();
  }
}

document.getElementById("logout-btn").addEventListener("click", () => {
  handleUnauthorized();
});

function renderIPLink(ip) {
  if (!ip || typeof ip !== "string" || !ip.trim()) {
    return `<span style="color:var(--dim)">—</span>`;
  }
  const cleanIp = ip.trim();
  const safeIp = cleanIp.replace(/'/g, "\\'");
  return `<span class="ip-link" onclick="openEntityModal('${safeIp}')">${cleanIp}</span>`;
}

function renderFeed(elId, events) {
  const el = document.getElementById(elId);
  if (!el) return;
  if (!events || events.length === 0) {
    el.innerHTML = '<div class="empty">No events yet.</div>';
    return;
  }
  el.innerHTML = events.slice(0, 50).map(e => {
    const levelClass = (e.threat_level || "low").toLowerCase();
    const ipPart = e.ip_address ? `${renderIPLink(e.ip_address)} — ` : "";
    const msg = e.message || `${e.category || ''}`;
    return `
      <div class="row ${levelClass}">
        <div class="time">${fmtTime(e.ts)}</div>
        <div class="sev ${levelClass}">${e.threat_level || 'LOW'}</div>
        <div>${ipPart}${msg}</div>
      </div>
    `;
  }).join("");
}

function renderRankedAlerts(events) {
  const el = document.getElementById("ranked-alerts-feed");
  if (!el) return;
  if (!events || events.length === 0) {
    el.innerHTML = '<div class="empty">No ranked alerts available.</div>';
    return;
  }
  // Sort top 20 events by threat_score descending
  const sorted = [...events].sort((a, b) => b.threat_score - a.threat_score).slice(0, 20);

  el.innerHTML = sorted.map(e => {
    const levelClass = (e.threat_level || "low").toLowerCase();
    const coldStartBadge = e.cold_start ? `<span class="badge-cold-start">❄ COLD START</span>` : '';
    const ipHtml = renderIPLink(e.ip_address);
    const attackType = e.attack_type || e.category || "unknown";
    const explanation = e.explanation || e.message || "No explanation available.";

    return `
      <div class="row ${levelClass}">
        <div class="time">${fmtTime(e.ts)}</div>
        <div class="sev ${levelClass}">${e.threat_level || 'LOW'} (${e.threat_score})</div>
        <div class="attack-badge">${attackType}</div>
        <div>${ipHtml} — ${explanation}</div>
        <div>${coldStartBadge}</div>
      </div>
    `;
  }).join("");
}

function renderTopIPs(rows) {
  const tbody = document.querySelector("#top-ips-table tbody");
  if (!tbody) return;
  if (!rows || rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="color:var(--dim)">No data yet.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td>${renderIPLink(r.ip_address)}</td>
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

async function openEntityModal(ip) {
  if (!ip) return;
  activeEntityIp = ip;

  const modal = document.getElementById("entity-modal");
  if (modal) {
    document.getElementById("entity-modal-ip").textContent = ip;
    modal.classList.add("open");
  }

  await loadEntityHistory(ip);
}

function closeEntityModal() {
  const modal = document.getElementById("entity-modal");
  if (modal) {
    modal.classList.remove("open");
  }
  activeEntityIp = null;
}

async function loadEntityHistory(ip) {
  try {
    const res = await fetchJSON(`/api/entity/${encodeURIComponent(ip)}`);
    const events = res.data || [];
    renderEntityHistory(events);
  } catch (err) {
    console.error("Failed to load entity history for", ip, err);
  }
}

function renderEntityHistory(events) {
  // Sort events by timestamp ASC for line chart
  const sorted = [...events].sort((a, b) => a.ts - b.ts);

  const labels = sorted.map(e => fmtTime(e.ts));
  const scores = sorted.map(e => e.threat_score);
  const confidences = sorted.map(e => e.baseline_confidence !== undefined ? Math.round(e.baseline_confidence * 100) : 100);

  const ctx = document.getElementById("chart-entity-history");
  if (ctx) {
    if (entityChart) {
      entityChart.destroy();
    }
    entityChart = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Threat Score",
            data: scores,
            borderColor: "#f0563d",
            backgroundColor: "rgba(240, 86, 61, 0.15)",
            tension: 0.3,
            fill: true,
          },
          {
            label: "Baseline Confidence (%)",
            data: confidences,
            borderColor: "#4fd6e8",
            borderDash: [4, 4],
            tension: 0.1,
            fill: false,
          }
        ]
      },
      options: {
        responsive: true,
        scales: {
          x: { ticks: { color: "#6b7c88", font: { size: 10 } }, grid: { color: "#1e262d" } },
          y: { min: 0, max: 100, ticks: { color: "#6b7c88" }, grid: { color: "#1e262d" } },
        },
        plugins: {
          legend: { labels: { color: "#d8e0e6", font: { family: "IBM Plex Mono" } } }
        }
      }
    });
  }

  // Render Table (DESC order for latest events first)
  const tbody = document.querySelector("#entity-table tbody");
  if (!tbody) return;

  const descEvents = [...events].sort((a, b) => b.ts - a.ts);
  if (descEvents.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="color:var(--dim)">No event history found for this IP.</td></tr>';
    return;
  }

  tbody.innerHTML = descEvents.map(e => {
    const coldBadge = e.cold_start ? `<span class="badge-cold-start">❄ TRUE</span>` : '<span style="color:var(--dim)">FALSE</span>';
    return `
      <tr>
        <td>${fmtTime(e.ts)}</td>
        <td><strong style="color:${e.threat_color || '#d8e0e6'}">${e.threat_score}</strong> (${e.threat_level || 'LOW'})</td>
        <td>${e.attack_type || e.category || 'normal'}</td>
        <td>${coldBadge}</td>
        <td style="font-size:12px; color:var(--text)">${e.explanation || e.message || '—'}</td>
      </tr>
    `;
  }).join("");
}

async function refresh() {
  try {
    const [stats, timeline, topIps, logAlerts, networkAlerts, rankedAlerts] = await Promise.all([
      fetchJSON("/api/stats"),
      fetchJSON("/api/threats/timeline"),
      fetchJSON("/api/threats/top-ips"),
      fetchJSON("/api/alerts"),
      fetchJSON("/api/network/alerts"),
      fetchJSON("/api/alerts?sort=score&limit=100"),
    ]);
    document.getElementById("api-status").textContent = "connected";
    document.getElementById("api-status").className = "api-status ok";

    renderStats(stats.data);
    renderTimeline(timeline.data);
    renderTopIPs(topIps.data);
    renderFeed("log-alerts-feed", logAlerts.data.filter(e => e.source !== "network"));
    renderFeed("network-alerts-feed", networkAlerts.data);
    renderRankedAlerts(rankedAlerts.data);

    // If entity modal is currently open, silently refresh entity history without disrupting modal
    if (activeEntityIp && document.getElementById("entity-modal")?.classList.contains("open")) {
      loadEntityHistory(activeEntityIp);
    }
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
    const headers = {
      "Content-Type": "application/json",
      ...getAuthHeaders()
    };
    const res = await fetch(`${API}/api/analyse`, {
      method: "POST",
      headers: headers,
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
        &nbsp;·&nbsp; Anomaly: ${data.result.is_anomaly ? "Yes" : "No"}
        &nbsp;·&nbsp; Attack: <strong>${data.result.attack_type}</strong>
        <br><span style="font-size:12px; color:var(--dim)">Explanation: ${data.result.explanation}</span>`;
    }
    refresh();
  } catch (e) {
    console.error(e);
  }
});

// Run initial check
checkLoginState();
setInterval(refresh, 5000);
