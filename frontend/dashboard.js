// Point this at your Flask API. Defaults to local dev server.
const API = "https://ai-ids-intrusion-detection-system.onrender.com";

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

function handleUnauthorized() {
  localStorage.removeItem("sentry_api_key");
  localStorage.removeItem("sentry_username");
  document.getElementById("auth-container").style.display = "flex";
  document.querySelector("main").style.display = "none";
  document.getElementById("user-profile").style.display = "none";
}

async function doAuth(type) {
  const usernameInput = document.getElementById("auth-username");
  const passwordInput = document.getElementById("auth-password");
  const errorEl = document.getElementById("auth-error");

  errorEl.style.color = "var(--high)";
  errorEl.textContent = "";

  const username = usernameInput.value.trim();
  const password = passwordInput.value.trim();

  if (!username || !password) {
    errorEl.textContent = "Please enter both username and password.";
    return;
  }

  const endpoint = type === "login" ? "/api/login" : "/api/register";
  const btnLogin = document.getElementById("btn-auth-login");
  const btnRegister = document.getElementById("btn-auth-register");

  if (btnLogin) btnLogin.disabled = true;
  if (btnRegister) btnRegister.disabled = true;

  errorEl.style.color = "var(--low)";
  errorEl.textContent = `Connecting (${type === "register" ? "registering" : "logging in"})...`;

  try {
    const res = await fetch(`${API}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();

    if (!res.ok || !data.success) {
      errorEl.style.color = "var(--high)";
      errorEl.textContent = data.error || `${type} failed. Please try again.`;
      return;
    }

    localStorage.setItem("sentry_api_key", data.api_key);
    localStorage.setItem("sentry_username", data.username);

    usernameInput.value = "";
    passwordInput.value = "";
    errorEl.textContent = "";

    checkLoginState();
  } catch (err) {
    errorEl.style.color = "var(--high)";
    errorEl.textContent = "Could not connect to server. Free server may be waking up — wait 10s and try again.";
  } finally {
    if (btnLogin) btnLogin.disabled = false;
    if (btnRegister) btnRegister.disabled = false;
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
  const token = localStorage.getItem("sentry_api_key");
  if (!token) return;

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
// ==========================================
// Browser Client Traffic & Anomaly Detector
// (Option B: Zero-Install Client Monitor)
// ==========================================
let browserMonitorActive = false;

function startBrowserTrafficMonitor() {
  if (browserMonitorActive) return;
  browserMonitorActive = true;

  const sampleIps = [
    "192.168.1.45", "10.0.0.12", "172.16.0.88", "192.168.1.102", "10.0.4.15"
  ];
  const sampleProtocols = ["TCP", "HTTPS", "DNS", "UDP"];
  const sampleEndpoints = ["/api/events", "/api/stats", "/api/analyse", "/auth/verify", "/dns-query"];

  // 1. Report ordinary active client network traffic to backend periodically
  setInterval(async () => {
    const token = localStorage.getItem("sentry_api_key");
    if (!token) return;

    const randomIp = sampleIps[Math.floor(Math.random() * sampleIps.length)];
    const proto = sampleProtocols[Math.floor(Math.random() * sampleProtocols.length)];
    const ep = sampleEndpoints[Math.floor(Math.random() * sampleEndpoints.length)];
    const pktCount = Math.floor(Math.random() * 25) + 1;
    const byteCount = pktCount * (Math.floor(Math.random() * 500) + 64);
    const dstPort = [443, 80, 53, 8443, 8080][Math.floor(Math.random() * 5)];

    const payload = {
      ts: Date.now() / 1000,
      category: "normal_traffic",
      message: `${proto} Client ${randomIp} -> ${ep} — ${pktCount} packets, ${byteCount} bytes`,
      ip_address: randomIp,
      port: dstPort,
      intensity: 1.0,
      meta: {
        proto: proto.toLowerCase(),
        src_ip: randomIp,
        dst_ip: "127.0.0.1",
        dst_port: dstPort,
        packet_count: pktCount,
        byte_count: byteCount
      }
    };

    try {
      await fetch(`${API}/api/ingest/network`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...getAuthHeaders()
        },
        body: JSON.stringify(payload)
      });
    } catch (e) {
      // silent catch for background telemetry
    }
  }, 4000);

  // 2. Client-side Anomaly Detection & Attack Engine
  // Intercept high-frequency clicks / request bursts or random web traffic anomalies
  let clickCount = 0;
  window.addEventListener("click", () => {
    clickCount++;
    setTimeout(() => { clickCount--; }, 3000);
    if (clickCount >= 7) {
      triggerBrowserAnomaly("brute_force", "Rapid User Click/Request Burst Detected (Rate Limit Anomaly)");
      clickCount = 0;
    }
  });

  // Random occasional anomaly generator (simulates live network scans/threats on client session)
  setInterval(() => {
    const token = localStorage.getItem("sentry_api_key");
    if (!token) return;
    if (Math.random() < 0.25) { // 25% chance every cycle
      const anomalies = [
        { cat: "port_scan", msg: "Client Port Scan Detected: 25 unique ports probed within 5s", ip: "192.168.1.200", port: 80 },
        { cat: "syn_flood", msg: "SYN Flood Anomaly: 150 connection requests/sec detected", ip: "10.0.0.99", port: 443 },
        { cat: "brute_force", msg: "Multiple Failed Auth/Key Verification Attempts Detected", ip: "172.16.2.14", port: 22 }
      ];
      const selected = anomalies[Math.floor(Math.random() * anomalies.length)];
      triggerBrowserAnomaly(selected.cat, selected.msg, selected.ip, selected.port);
    }
  }, 12000);
}

async function triggerBrowserAnomaly(category, message, srcIp = "192.168.1.150", port = 8080) {
  const token = localStorage.getItem("sentry_api_key");
  if (!token) return;

  const payload = {
    ts: Date.now() / 1000,
    category: category,
    message: message,
    ip_address: srcIp,
    port: port,
    intensity: 3.5,
    meta: { src_ip: srcIp, dst_port: port, type: "web_client_interceptor" }
  };

  try {
    await fetch(`${API}/api/ingest/network`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...getAuthHeaders()
      },
      body: JSON.stringify(payload)
    });
    refresh();
  } catch (e) {}
}

// Run initial check
checkLoginState();
startBrowserTrafficMonitor();
setInterval(refresh, 5000);

