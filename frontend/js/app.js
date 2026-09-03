/**
 * NEXUS GRAPH // Main Application Controller & Forensic Inspector
 * Handles:
 * - Tab 1: Syndicate Network Graph (D3.js on Sky Blue Canvas)
 * - Tab 2: Age Group Impact Graph (Dedicated Chart.js Grouped Bars)
 * - Tab 3: Gender & Crime Vulnerability Graph (Dedicated Chart.js Stacked Horizontal & Donut)
 * - Tab 4: Geospatial Crime Heatmap (Leaflet.js on Dark Map)
 * - Tab 5: Threat Intelligence Center (SIM Churn, Logistics, BTS)
 * - Tab 6: BSA 2023 Evidence Registry (SHA-256 & PDF Downloads)
 * - Tab 7: Data Ingestion Hub (Live NLP & Bulk CSV Upload)
 */

const API_BASE = "";

let visualizer = null;
let currentGraphData = { nodes: [], links: [] };
let activeFilter = "ALL";
let minRiskThreshold = 0.0;
let threatsOnlyFilter = false;

// Geospatial Heatmap Map & Layers
let crimeMap = null;
let heatLayer = null;
let markersLayerGroup = null;
let towersLayerGroup = null;
let corridorsLayerGroup = null;
let heatmapDataCache = null;

// Dedicated Analytics Charts
let ageDedicatedChart = null;
let genderDedicatedChart = null;
let genderDonutChart = null;
let demographicsDataCache = null;

// Sample FIR Templates for quick demo injection
const SAMPLE_FIRS = {
    crypto: {
        fir_number: "FIR-2026-DEL-109",
        police_station: "Special Cell Cyber Crime, New Delhi",
        date: "2026-08-30",
        state: "Delhi",
        text: "Interception of interstate extortion racket. Suspect Vikram Singhaniya operating car registration DL-01-AB-1234 transferred Rs 28,00,000 to mule account 918234509122 held at Rohini, Delhi. Suspect Vikram Singhania coordinated via mobile 9810011223 near tower TOWER-DEL-402 with co-accused Amit Verma."
    },
    phishing: {
        fir_number: "FIR-2026-BLR-310",
        police_station: "Cyber Economic Offences, Bengaluru",
        date: "2026-08-31",
        state: "Karnataka",
        text: "Extortion network case. Accused Raahul Mondal and Dinesh Kumar coerced victim into transferring Rs 22,00,000 into SBI account 309182746519. Suspect Rahul Mondal was observed operating getaway vehicle KA-05-XY-9999 from Koramangala, Bengaluru using mobile 9845012345."
    },
    hawala: {
        fir_number: "FIR-2026-KOL-412",
        police_station: "STF Cyber Cell, Kolkata",
        date: "2026-08-31",
        state: "West Bengal",
        text: "Cross-border Hawala syndicate alert. Kingpin Kabir Sheikh routed Rs 65,00,000 through mule account 220193847561. Accused Farhan Akhtar driving vehicle WB-02-AK-9876 coordinated with Ananya Sen (Account: 881920394857) at Salt Lake, Kolkata utilizing mobile 9830077665 near cell tower TOWER-KOL-109."
    }
};

document.addEventListener("DOMContentLoaded", () => {
    initVisualizer();
    bindUIEvents();
    checkHealth();
    loadGraph();
    loadThreatCenter();
});

function initVisualizer() {
    visualizer = new ForensicGraphVisualizer("#network-svg", handleNodeSelection);
}

// Systematic Multi-View Switcher for 7 Dedicated Tabs
window.switchView = function(viewName) {
    // Hide all views
    document.querySelectorAll(".app-view").forEach(el => {
        el.classList.add("d-none");
        el.classList.remove("active");
    });

    // Deactivate all nav pills
    document.querySelectorAll("#mainNavTabs .nav-link").forEach(btn => btn.classList.remove("active"));

    // Activate selected view
    const targetView = document.getElementById(`view-${viewName}`);
    const targetBtn = document.getElementById(`tab-btn-${viewName}`);
    if (targetView) {
        targetView.classList.remove("d-none");
        targetView.classList.add("active");
    }
    if (targetBtn) {
        targetBtn.classList.add("active");
    }

    if (viewName === "graph" && visualizer) {
        setTimeout(() => visualizer.handleResize(), 50);
    } else if (viewName === "age") {
        loadAgeAnalyticsData();
    } else if (viewName === "gender") {
        loadGenderAnalyticsData();
    } else if (viewName === "heatmap") {
        if (!crimeMap) {
            initHeatmap();
        } else {
            setTimeout(() => crimeMap.invalidateSize(), 100);
        }
        loadHeatmapData();
    } else if (viewName === "bsa") {
        loadFullBSARegistry();
    } else if (viewName === "threats") {
        loadThreatCenter();
    }
};

// ==========================================
// TAB 2: AGE GROUP IMPACT GRAPH CONTROLLER
// ==========================================
async function loadAgeAnalyticsData() {
    try {
        if (!demographicsDataCache) {
            const res = await fetch(`${API_BASE}/api/analytics/demographics`);
            if (!res.ok) throw new Error("Failed to load age analytics");
            demographicsDataCache = await res.json();
        }
        const data = demographicsDataCache;

        // 1. Update Age KPI Cards
        if (data.age_group_summary) {
            const y = data.age_group_summary["18_25"];
            if (y) document.getElementById("age-kpi-youth").innerText = `${y.count} Victims (${y.percentage}%)`;
            const yp = data.age_group_summary["26_35"];
            if (yp) document.getElementById("age-kpi-youngpros").innerText = `${yp.count} Victims (${yp.percentage}%)`;
            const ex = data.age_group_summary["36_50"];
            if (ex) document.getElementById("age-kpi-execs").innerText = `${ex.count} Victims (${ex.percentage}%)`;
            const sn = data.age_group_summary["50_plus"];
            if (sn) document.getElementById("age-kpi-seniors").innerText = `${sn.count} Victims (${sn.percentage}%)`;
        }

        // 2. Render Dedicated Age Group Multi-Bar Chart
        const ctx = document.getElementById("chart-age-dedicated");
        if (ctx && typeof Chart !== "undefined") {
            const suspects = data.suspect_age_matrix || [];
            const labels = suspects.map(s => s.suspect_name);
            const data18_25 = suspects.map(s => s.age_18_25);
            const data26_35 = suspects.map(s => s.age_26_35);
            const data36_50 = suspects.map(s => s.age_36_50);
            const data50Plus = suspects.map(s => s.age_50_plus);

            if (ageDedicatedChart) ageDedicatedChart.destroy();

            ageDedicatedChart = new Chart(ctx, {
                type: "bar",
                data: {
                    labels: labels,
                    datasets: [
                        { label: "18–25 (College Students / Youth)", data: data18_25, backgroundColor: "#10b981", borderRadius: 4 },
                        { label: "26–35 (Young Working Pros)", data: data26_35, backgroundColor: "#3b82f6", borderRadius: 4 },
                        { label: "36–50 (Execs & Business Leads)", data: data36_50, backgroundColor: "#8b5cf6", borderRadius: 4 },
                        { label: "50+ (Senior Citizens & Pensioners)", data: data50Plus, backgroundColor: "#ef4444", borderRadius: 4 }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: "top", labels: { color: "#94a3b8", font: { family: "JetBrains Mono", size: 11 } } },
                        tooltip: {
                            callbacks: {
                                footer: (items) => {
                                    const idx = items[0].dataIndex;
                                    const s = suspects[idx];
                                    return `Primary Target: ${s.primary_target_group}\nTraced Loss: ₹${(s.total_loss/100000).toFixed(1)} Lakhs`;
                                }
                            }
                        }
                    },
                    scales: {
                        x: { ticks: { color: "#cbd5e1", font: { weight: "bold", size: 11 } }, grid: { color: "rgba(255,255,255,0.05)" } },
                        y: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" }, title: { display: true, text: "Number of Victims", color: "#64748b" } }
                    }
                }
            });
        }

        // 3. Update Age Suspect Profiler Box
        updateAgeSuspectProfiler();

        // 4. Populate Age Suspects Table
        const tbody = document.getElementById("table-age-suspects-tbody");
        if (tbody) {
            let html = "";
            (data.suspect_age_matrix || []).forEach(s => {
                html += `
                    <tr>
                        <td class="text-light fw-bold">${escapeHtml(s.suspect_name)}</td>
                        <td class="text-secondary">${escapeHtml(s.primary_crime)}</td>
                        <td class="text-success fw-bold">${s.age_18_25}</td>
                        <td class="text-primary fw-bold">${s.age_26_35}</td>
                        <td class="text-purple fw-bold" style="color: #c084fc;">${s.age_36_50}</td>
                        <td class="text-danger fw-bold">${s.age_50_plus}</td>
                        <td class="text-warning font-mono fw-bold">₹${(s.total_loss/100000).toFixed(1)}L</td>
                    </tr>
                `;
            });
            tbody.innerHTML = html;
        }

    } catch (err) {
        console.error("Error loading age analytics:", err);
    }
}

function updateAgeSuspectProfiler() {
    if (!demographicsDataCache || !demographicsDataCache.suspect_age_matrix) return;
    const select = document.getElementById("select-age-suspect");
    const name = select ? select.value : "Rahul Mondal";
    const suspect = demographicsDataCache.suspect_age_matrix.find(s => s.suspect_name === name) || demographicsDataCache.suspect_age_matrix[0];

    if (suspect) {
        document.getElementById("age-prof-name").innerText = suspect.suspect_name;
        document.getElementById("age-prof-crime").innerText = suspect.primary_crime;
        document.getElementById("age-prof-loss").innerText = `₹${(suspect.total_loss / 100000).toFixed(1)}L Total Loss`;
        document.getElementById("age-prof-target").innerText = suspect.primary_target_group;
        document.getElementById("age-prof-breakdown").innerText = `18-25: ${suspect.age_18_25} | 26-35: ${suspect.age_26_35} | 36-50: ${suspect.age_36_50} | 50+: ${suspect.age_50_plus}`;

        const btn = document.getElementById("btn-age-prof-inspect");
        if (btn) {
            btn.onclick = () => {
                switchView("graph");
                visualizer.focusOnNode(suspect.canonical_id);
            };
        }
    }
}

// ==========================================
// TAB 3: GENDER & CRIME GRAPH CONTROLLER
// ==========================================
async function loadGenderAnalyticsData() {
    try {
        if (!demographicsDataCache) {
            const res = await fetch(`${API_BASE}/api/analytics/demographics`);
            if (!res.ok) throw new Error("Failed to load gender analytics");
            demographicsDataCache = await res.json();
        }
        const data = demographicsDataCache;

        // 1. Update Gender KPIs
        if (data.gender_summary) {
            document.getElementById("gender-kpi-female").innerText = `${data.gender_summary.female_count} Female Victims (${data.gender_summary.female_percentage}%)`;
            document.getElementById("gender-kpi-male").innerText = `${data.gender_summary.male_count} Male Victims (${data.gender_summary.male_percentage}%)`;
            document.getElementById("gender-kpi-total").innerText = `${data.gender_summary.total_victims} Total Victims Traced`;
        }

        // 2. Render Dedicated Horizontal Stacked Bar Chart
        const ctxBar = document.getElementById("chart-gender-dedicated");
        if (ctxBar && typeof Chart !== "undefined") {
            const crimes = data.gender_crime_matrix || [];
            const labels = crimes.map(c => c.crime_category);
            const maleData = crimes.map(c => c.male_victims);
            const femaleData = crimes.map(c => c.female_victims);
            const otherData = crimes.map(c => c.other_victims);

            if (genderDedicatedChart) genderDedicatedChart.destroy();

            genderDedicatedChart = new Chart(ctxBar, {
                type: "bar",
                data: {
                    labels: labels,
                    datasets: [
                        { label: "Female Victims", data: femaleData, backgroundColor: "#f59e0b", borderRadius: 4 },
                        { label: "Male Victims", data: maleData, backgroundColor: "#0284c7", borderRadius: 4 },
                        { label: "Other / Transgender", data: otherData, backgroundColor: "#8b5cf6", borderRadius: 4 }
                    ]
                },
                options: {
                    indexAxis: "y",
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: "top", labels: { color: "#94a3b8", font: { family: "JetBrains Mono", size: 11 } } },
                        tooltip: {
                            callbacks: {
                                afterLabel: (item) => {
                                    const c = crimes[item.dataIndex];
                                    return `Alert: ${c.primary_vulnerability}\nFemale Ratio: ${c.female_percentage}%`;
                                }
                            }
                        }
                    },
                    scales: {
                        x: { stacked: true, ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" } },
                        y: { stacked: true, ticks: { color: "#cbd5e1", font: { size: 10.5, weight: "500" } }, grid: { color: "rgba(255,255,255,0.05)" } }
                    }
                }
            });
        }

        // 3. Render Dedicated Donut Chart
        const ctxDonut = document.getElementById("chart-gender-donut");
        if (ctxDonut && typeof Chart !== "undefined") {
            const gs = data.gender_summary || { male_count: 226, female_count: 186, other_count: 9 };
            if (genderDonutChart) genderDonutChart.destroy();

            genderDonutChart = new Chart(ctxDonut, {
                type: "doughnut",
                data: {
                    labels: ["Male Victims", "Female Victims", "Other / Non-Binary"],
                    datasets: [{
                        data: [gs.male_count, gs.female_count, gs.other_count],
                        backgroundColor: ["#0284c7", "#f59e0b", "#8b5cf6"],
                        borderColor: "#0f172a",
                        borderWidth: 3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: "bottom", labels: { color: "#cbd5e1", font: { family: "JetBrains Mono", size: 10 } } }
                    }
                }
            });
        }

        // 4. Populate Dedicated Gender Table
        const tbody = document.getElementById("table-gender-dedicated-tbody");
        if (tbody) {
            let html = "";
            (data.gender_crime_matrix || []).forEach(g => {
                const femaleBadge = g.female_percentage >= 50.0 ? "text-bg-warning text-dark" : "text-bg-secondary";
                html += `
                    <tr>
                        <td class="text-light fw-bold">${escapeHtml(g.crime_category)}</td>
                        <td class="text-info fw-bold">${g.male_victims}</td>
                        <td class="text-warning fw-bold">${g.female_victims}</td>
                        <td class="text-purple fw-bold" style="color: #c084fc;">${g.other_victims}</td>
                        <td class="text-light fw-bold">${g.total_victims}</td>
                        <td><span class="badge ${femaleBadge}">${g.female_percentage}%</span></td>
                        <td class="text-warning">${escapeHtml(g.primary_vulnerability)}</td>
                    </tr>
                `;
            });
            tbody.innerHTML = html;
        }

    } catch (err) {
        console.error("Error loading gender analytics:", err);
    }
}

// ==========================================
// TAB 4: GEOSPATIAL HEATMAP CONTROLLER
// ==========================================
function initHeatmap() {
    const container = document.getElementById("crime-heatmap-container");
    if (!container) return;

    crimeMap = L.map("crime-heatmap-container", {
        center: [22.5, 79.0],
        zoom: 5,
        zoomControl: true
    });

    // Dark Map Tiles (CartoDB Dark Matter)
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        attribution: '&copy; <a href="https://carto.com/">CARTO</a> &copy; OpenStreetMap contributors',
        subdomains: "abcd",
        maxZoom: 18
    }).addTo(crimeMap);

    markersLayerGroup = L.layerGroup().addTo(crimeMap);
    towersLayerGroup = L.layerGroup().addTo(crimeMap);
    corridorsLayerGroup = L.layerGroup().addTo(crimeMap);

    // Layer control toggles
    document.getElementById("layer-toggle-heat")?.addEventListener("change", (e) => {
        if (heatLayer) {
            if (e.target.checked) crimeMap.addLayer(heatLayer);
            else crimeMap.removeLayer(heatLayer);
        }
    });

    document.getElementById("layer-toggle-markers")?.addEventListener("change", (e) => {
        if (e.target.checked) crimeMap.addLayer(markersLayerGroup);
        else crimeMap.removeLayer(markersLayerGroup);
    });

    document.getElementById("layer-toggle-towers")?.addEventListener("change", (e) => {
        if (e.target.checked) crimeMap.addLayer(towersLayerGroup);
        else crimeMap.removeLayer(towersLayerGroup);
    });

    document.getElementById("layer-toggle-corridors")?.addEventListener("change", (e) => {
        if (e.target.checked) crimeMap.addLayer(corridorsLayerGroup);
        else crimeMap.removeLayer(corridorsLayerGroup);
    });

    document.getElementById("btn-reset-map")?.addEventListener("click", () => {
        crimeMap.setView([22.5, 79.0], 5);
    });
}

async function loadHeatmapData() {
    try {
        const res = await fetch(`${API_BASE}/api/heatmap`);
        if (!res.ok) throw new Error("Failed to load heatmap data");
        const data = await res.json();
        heatmapDataCache = data;

        // Update Ribbon Metrics
        if (data.summary) {
            document.getElementById("heatmap-top-hub").innerText = data.summary.top_crime_hub || "Delhi NCR";
            document.getElementById("heatmap-total-cities").innerText = data.summary.total_jurisdictions || 6;
            document.getElementById("heatmap-total-towers").innerText = data.summary.active_cell_towers || 4;
            document.getElementById("heatmap-total-corridors").innerText = data.summary.monitored_transit_corridors || 3;
            const fraud = data.summary.total_fraud_volume_mapped || 0;
            document.getElementById("heatmap-total-fraud").innerText = `₹${(fraud / 10000000).toFixed(2)}Cr`;
        }

        if (!crimeMap) return;

        // 1. Render Heatmap Density Layer
        if (heatLayer) crimeMap.removeLayer(heatLayer);
        const heatPoints = (data.points || []).map(p => [p.lat, p.lng, p.intensity * 1.5]);

        if (typeof L.heatLayer === "function") {
            heatLayer = L.heatLayer(heatPoints, {
                radius: 42,
                blur: 28,
                maxZoom: 12,
                gradient: { 0.2: "#3b82f6", 0.5: "#10b981", 0.7: "#f59e0b", 1.0: "#ef4444" }
            });
            if (document.getElementById("layer-toggle-heat")?.checked) {
                heatLayer.addTo(crimeMap);
            }
        }

        // 2. Render City Hub Markers
        markersLayerGroup.clearLayers();
        (data.points || []).forEach(p => {
            const size = Math.max(Math.round(p.intensity * 32), 18);
            const customIcon = L.divIcon({
                className: "custom-div-icon",
                html: `<div class="map-city-marker" style="width: ${size}px; height: ${size}px; font-size: ${size > 22 ? 11 : 9}px;">${p.fir_count || '📍'}</div>`,
                iconSize: [size, size],
                iconAnchor: [size / 2, size / 2]
            });

            const marker = L.marker([p.lat, p.lng], { icon: customIcon });
            const fraudFormatted = p.fraud_volume >= 10000000 ? `₹${(p.fraud_volume / 10000000).toFixed(2)}Cr` : `₹${(p.fraud_volume / 100000).toFixed(1)}L`;

            marker.bindPopup(`
                <div class="p-1">
                    <div class="d-flex justify-content-between align-items-center mb-1">
                        <span class="badge text-bg-danger">${p.high_risk ? "High-Risk Hub" : "Active Hub"}</span>
                        <span class="font-mono text-warning tiny-text">Intensity: ${p.intensity}</span>
                    </div>
                    <h6 class="fw-bold text-light mb-1">${escapeHtml(p.city)} Jurisdiction</h6>
                    <div class="tiny-text text-secondary mb-1">• <strong>FIR Cases:</strong> ${p.fir_count} cases lodged</div>
                    <div class="tiny-text text-secondary mb-1">• <strong>Tracked Suspects:</strong> ${p.suspect_count} key entities</div>
                    <div class="tiny-text text-secondary mb-2">• <strong>Traced Fraud:</strong> <span class="text-success font-mono">${fraudFormatted}</span></div>
                    <button class="btn btn-xs btn-outline-primary w-100" onclick="switchView('graph'); visualizer.focusOnNode('LOCATION:${p.city.toLowerCase()}');">
                        <i class="bi bi-diagram-3 me-1"></i>Inspect In Syndicate Graph
                    </button>
                </div>
            `);
            markersLayerGroup.addLayer(marker);
        });

        // 3. Render BTS Cell Towers
        towersLayerGroup.clearLayers();
        (data.towers || []).forEach(t => {
            const towerIcon = L.divIcon({
                className: "custom-div-icon",
                html: `<div class="map-tower-marker" style="width: 26px; height: 26px;"><i class="bi bi-broadcast"></i></div>`,
                iconSize: [26, 26],
                iconAnchor: [13, 13]
            });

            const towerMarker = L.marker([t.lat, t.lng], { icon: towerIcon });
            towerMarker.bindPopup(`
                <div class="p-1">
                    <div class="d-flex justify-content-between align-items-center mb-1">
                        <span class="badge text-bg-purple" style="background:#8b5cf6 !important;">BTS Cell Tower</span>
                        <span class="badge text-bg-danger tiny-text">Co-Location Flagged</span>
                    </div>
                    <h6 class="fw-bold text-light mb-1">${escapeHtml(t.tower_id)}</h6>
                    <div class="tiny-text text-secondary mb-1">Location: ${escapeHtml(t.city)}</div>
                    <div class="tiny-text text-secondary mb-1">• <strong>Intercepted Call Pings:</strong> ${t.call_pings}</div>
                    <div class="tiny-text text-secondary mb-2">• <strong>Co-Located Phones:</strong> <span class="text-info font-mono">${(t.phones || []).join(", ")}</span></div>
                    <button class="btn btn-xs btn-outline-info w-100" onclick="switchView('graph'); focusScenario('bts');">
                        <i class="bi bi-diagram-3 me-1"></i>Inspect Tower Connections
                    </button>
                </div>
            `);
            towersLayerGroup.addLayer(towerMarker);
        });

        // 4. Render Logistics & Transit Corridors
        corridorsLayerGroup.clearLayers();
        (data.corridors || []).forEach(c => {
            const polyline = L.polyline([c.from_coords, c.to_coords], {
                color: c.alert ? "#f59e0b" : "#3b82f6",
                weight: 3.5,
                opacity: 0.85,
                dashArray: c.alert ? "8, 6" : "4, 4"
            });

            polyline.bindPopup(`
                <div class="p-1">
                    <div class="d-flex justify-content-between align-items-center mb-1">
                        <span class="badge ${c.alert ? 'text-bg-warning text-dark' : 'text-bg-info'}">Transit Corridor</span>
                        ${c.alert ? '<span class="badge text-bg-danger tiny-text">Anti-Trafficking Flag</span>' : ''}
                    </div>
                    <h6 class="fw-bold text-light mb-1">${escapeHtml(c.name)}</h6>
                    <div class="tiny-text text-secondary mb-1">• <strong>Transit Modes:</strong> ${escapeHtml(c.transit_mode)}</div>
                    <div class="tiny-text text-secondary mb-2">• <strong>Flagged Hotel Stays:</strong> ${c.hotel_stays} OYO/Treebo stays</div>
                    <button class="btn btn-xs btn-outline-warning w-100" onclick="switchView('graph'); focusScenario('logistics');">
                        <i class="bi bi-diagram-3 me-1"></i>Inspect Logistics Trail
                    </button>
                </div>
            `);
            corridorsLayerGroup.addLayer(polyline);
        });

    } catch (err) {
        console.error("Error loading heatmap data:", err);
    }
}

// ==========================================
// TAB 1: D3 FORCE GRAPH FORENSIC INSPECTOR
// ==========================================
function handleNodeSelection(node) {
    const content = document.getElementById("sidepanel-content");

    if (!node) {
        content.innerHTML = `
            <!-- Interactive Welcome & Quick Start Showcase -->
            <div class="card bg-surface border-secondary-subtle mb-3">
                <div class="card-body p-3">
                    <div class="d-flex align-items-center gap-2 mb-2">
                        <i class="bi bi-compass-fill text-warning fs-5"></i>
                        <h6 class="fw-bold text-light mb-0">Evidence Inspector</h6>
                    </div>
                    <p class="tiny-text text-secondary mb-2">
                        Select any node on the <strong>Sky Blue Canvas</strong> to inspect its betweenness centrality broker power, forensic aliases, and cryptographic SHA-256 seal.
                    </p>
                </div>
            </div>

            <!-- Guided 1-Click Investigation Scenarios -->
            <div class="mb-3">
                <label class="form-label text-secondary tiny-text fw-bold text-uppercase tracking-wide mb-1.5 d-block">
                    <i class="bi bi-stars text-warning me-1"></i>Quick Threat Demos:
                </label>
                <div class="d-flex flex-column gap-2">
                    <!-- Scenario 1 -->
                    <div class="card bg-dark border-danger-subtle cursor-pointer hover-card p-2.5" onclick="focusScenario('sim_churn')">
                        <div class="d-flex justify-content-between align-items-center mb-1">
                            <span class="badge text-bg-danger tiny-text"><i class="bi bi-sim me-1"></i>SIM Churn Match</span>
                            <span class="tiny-text text-danger fw-bold">100% Target Overlap</span>
                        </div>
                        <div class="small fw-semibold text-light mb-0.5">Phone 9820099881 → 9899011222</div>
                        <div class="tiny-text text-secondary">Suspect switched SIMs while calling the exact same 4 accomplices.</div>
                    </div>

                    <!-- Scenario 2 -->
                    <div class="card bg-dark border-secondary cursor-pointer hover-card p-2.5" onclick="focusScenario('vehicle')">
                        <div class="d-flex justify-content-between align-items-center mb-1">
                            <span class="badge text-bg-purple tiny-text" style="background: #7c3aed !important;"><i class="bi bi-car-front me-1"></i>Vehicle & Fuzzy Suspect</span>
                            <span class="tiny-text text-info fw-bold">Levenshtein &le; 2</span>
                        </div>
                        <div class="small fw-semibold text-light mb-0.5">Car DL-01-AB-1234 & Vikram Singhania</div>
                        <div class="tiny-text text-secondary">Unified 'Vikram Singhania' and 'Vikram Singhaniya' aliases.</div>
                    </div>

                    <!-- Scenario 3 -->
                    <div class="card bg-dark border-warning-subtle cursor-pointer hover-card p-2.5" onclick="focusScenario('logistics')">
                        <div class="d-flex justify-content-between align-items-center mb-1">
                            <span class="badge text-bg-warning text-dark tiny-text"><i class="bi bi-airplane-engines me-1"></i>Logistics Threat</span>
                            <span class="tiny-text text-warning fw-bold">Women's Safety Flag</span>
                        </div>
                        <div class="small fw-semibold text-light mb-0.5">Mule Account 440192837461 (Tariq Ali)</div>
                        <div class="tiny-text text-secondary">Flagged for repetitive transit tickets + frequent short hotel stays.</div>
                    </div>

                    <!-- Scenario 4 -->
                    <div class="card bg-dark border-info-subtle cursor-pointer hover-card p-2.5" onclick="focusScenario('bts')">
                        <div class="d-flex justify-content-between align-items-center mb-1">
                            <span class="badge text-bg-info tiny-text"><i class="bi bi-broadcast me-1"></i>BTS Co-Location</span>
                            <span class="tiny-text text-info fw-bold">&le; 10 min Window</span>
                        </div>
                        <div class="small fw-semibold text-light mb-0.5">Tower TOWER-DEL-402 (Delhi)</div>
                        <div class="tiny-text text-secondary">Phones 9810011223 & 9811099887 pinged within 3.6 minutes.</div>
                    </div>
                </div>
            </div>
        `;
        return;
    }

    renderNodeDetails(node);
}

async function renderNodeDetails(node) {
    const content = document.getElementById("sidepanel-content");
    content.innerHTML = `
        <div class="d-flex justify-content-center py-4">
            <div class="spinner-border spinner-border-sm text-danger" role="status"></div>
            <span class="ms-2 small text-secondary">Fetching forensic records...</span>
        </div>
    `;

    try {
        const res = await fetch(`${API_BASE}/api/node/${encodeURIComponent(node.id)}`);
        if (!res.ok) throw new Error("Node details not found");
        const data = await res.json();

        const riskPercent = Math.round((data.risk_score || 0) * 100);
        const riskColorClass = data.risk_score >= 0.70 ? "bg-danger" : (data.risk_score >= 0.40 ? "bg-warning text-dark" : "bg-success");
        const typeBadgeColor = {
            "Suspect": "text-bg-danger",
            "BankAccount": "text-bg-warning text-dark",
            "Location": "text-bg-success",
            "FIR": "text-bg-info",
            "Phone": "text-bg-primary",
            "Vehicle": "text-bg-purple"
        }[data.type] || "text-bg-secondary";

        let alertHtml = "";
        if (data.alert) {
            alertHtml = `
                <div class="alert alert-danger py-2 px-2.5 mb-2.5 border-danger small">
                    <div class="fw-bold d-flex align-items-center gap-1 mb-1">
                        <i class="bi bi-exclamation-octagon-fill"></i>
                        <span>Active Threat Warning Flagged</span>
                    </div>
                    <ul class="mb-0 ps-3 tiny-text">
                        ${(data.alert_reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join("")}
                    </ul>
                </div>
            `;
        }

        const centralityVal = parseFloat(data.centrality_score || 0.0).toFixed(4);
        const pagerankVal = parseFloat(data.pagerank || 0.0).toFixed(4);
        const sha256 = data.sha256_hash || "fd0da1119eb28c27f867209976f89afc7c4ed64982d9b6789c67540aae2c576b";

        let html = `
            <!-- Node Header Badge -->
            <div class="d-flex justify-content-between align-items-start mb-2">
                <div>
                    <span class="badge ${typeBadgeColor} mb-1">${escapeHtml(data.type)}</span>
                    <h5 class="fw-bold text-light mb-0">${escapeHtml(data.label)}</h5>
                    <span class="tiny-text font-mono text-secondary">${escapeHtml(data.id)}</span>
                </div>
                <div class="text-end">
                    <span class="badge ${riskColorClass} font-mono fs-6">${riskPercent}%</span>
                    <div class="tiny-text text-secondary">Risk Score</div>
                </div>
            </div>

            ${data.type === "Suspect" ? `
            <!-- Inter-Agency Police Station APB Broadcast Button -->
            <button class="btn btn-sm btn-danger w-100 mb-2.5 d-flex align-items-center justify-content-center gap-1.5 shadow" onclick="triggerAPBBroadcast('${escapeHtml(data.id)}')">
                <i class="bi bi-broadcast"></i>
                <span class="fw-bold">🚨 Broadcast APB to All Police Stations</span>
            </button>
            ` : ''}

            ${alertHtml}

            <!-- Algorithmic Metric Breakdown -->
            <div class="card bg-surface border-secondary-subtle mb-3">
                <div class="card-body p-2.5">
                    <div class="row g-2 text-center tiny-text">
                        <div class="col-4">
                            <div class="text-secondary">Centrality</div>
                            <div class="fw-bold text-info font-mono">${centralityVal}</div>
                        </div>
                        <div class="col-4">
                            <div class="text-secondary">PageRank</div>
                            <div class="fw-bold text-warning font-mono">${pagerankVal}</div>
                        </div>
                        <div class="col-4">
                            <div class="text-secondary">Degree</div>
                            <div class="fw-bold text-light font-mono">${data.degree || 0}</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Section 63(4) BSA 2023 Digital Seal -->
            <div class="card bg-surface border-info-subtle mb-3">
                <div class="card-header bg-darker py-1 px-2.5 border-secondary d-flex justify-content-between align-items-center">
                    <span class="tiny-text fw-bold text-info"><i class="bi bi-file-earmark-lock2 me-1"></i>Section 63(4) BSA 2023 Seal</span>
                    <button class="btn btn-xs btn-outline-info py-0 px-1" onclick="copyToClipboard('${sha256}')" title="Copy SHA-256 Digest">Copy</button>
                </div>
                <div class="card-body p-2 font-mono tiny-text text-break text-info bg-dark">
                    ${sha256}
                </div>
                <div class="card-footer bg-darker py-1.5 px-2 text-end">
                    <a href="${API_BASE}/api/bsa-certificate/download?sha256_hash=${encodeURIComponent(sha256)}&case_reference=${encodeURIComponent(data.label)}" class="btn btn-xs btn-info w-100" target="_blank">
                        <i class="bi bi-file-earmark-pdf-fill me-1"></i>Download Court Certificate (PDF)
                    </a>
                </div>
            </div>

            <!-- Connected Syndicate Links -->
            <div class="card bg-surface border-secondary-subtle mb-3">
                <div class="card-header bg-darker py-1.5 px-2.5 border-secondary-subtle">
                    <span class="tiny-text fw-bold text-secondary text-uppercase"><i class="bi bi-link-45deg me-1"></i>Connections (${(data.connections || []).length})</span>
                </div>
                <div class="card-body p-1.5 overflow-y-auto" style="max-height: 180px;">
                    ${renderConnectionsList(data.connections)}
                </div>
            </div>
        `;

        if (data.raw_fir_text) {
            html += `
                <!-- Raw FIR Narrative -->
                <div class="card bg-surface border-secondary-subtle">
                    <div class="card-header bg-darker py-1.5 px-2.5 border-secondary-subtle">
                        <span class="tiny-text fw-bold text-secondary text-uppercase"><i class="bi bi-file-text me-1"></i>Raw FIR Evidence</span>
                    </div>
                    <div class="card-body p-2.5 tiny-text text-secondary bg-dark" style="max-height: 140px; overflow-y: auto;">
                        ${highlightEvidence(data.raw_fir_text, data.label)}
                    </div>
                </div>
            `;
        }

        content.innerHTML = html;
    } catch (err) {
        content.innerHTML = `
            <div class="alert alert-danger py-2 px-3 small">
                Failed to load node details: ${escapeHtml(err.message)}
            </div>
        `;
    }
}

function renderConnectionsList(connections) {
    if (!connections || connections.length === 0) {
        return `<div class="text-secondary tiny-text p-2 text-center">No active syndicate links.</div>`;
    }

    return connections.map(conn => {
        const isOut = conn.direction === "outgoing";
        const icon = isOut ? "bi-arrow-right-circle text-danger" : "bi-arrow-left-circle text-success";
        const amtBadge = conn.amount ? `<span class="badge text-bg-warning text-dark tiny-text ms-1">₹${(conn.amount / 100000).toFixed(1)}L</span>` : "";
        
        return `
            <div class="d-flex align-items-center justify-content-between p-1.5 border-bottom border-secondary-subtle hover-item cursor-pointer" onclick="visualizer.focusOnNode('${escapeHtml(conn.target_id)}')">
                <div class="d-flex align-items-center gap-1.5 text-truncate" style="max-width: 210px;">
                    <i class="bi ${icon}"></i>
                    <span class="tiny-text fw-bold text-light">${escapeHtml(conn.target_label || conn.target_id)}</span>
                </div>
                <div class="d-flex align-items-center">
                    ${amtBadge}
                    <span class="badge bg-dark text-secondary tiny-text ms-1">${escapeHtml(conn.type)}</span>
                </div>
            </div>
        `;
    }).join("");
}

function highlightEvidence(text, term) {
    if (!text || !term) return escapeHtml(text || "");
    const escapedText = escapeHtml(text);
    const regex = new RegExp(`(${escapeRegex(term)})`, 'gi');
    return escapedText.replace(regex, '<mark class="bg-warning text-dark px-1 rounded">$1</mark>');
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function loadGraph() {
    try {
        let url = `${API_BASE}/api/network?min_risk=${minRiskThreshold}`;
        if (activeFilter && activeFilter !== "ALL") {
            url += `&node_type=${encodeURIComponent(activeFilter)}`;
        }
        if (threatsOnlyFilter) {
            url += `&threats_only=true`;
        }

        const res = await fetch(url);
        if (!res.ok) throw new Error("Failed to fetch graph data");
        const data = await res.json();
        
        currentGraphData = data;
        updateMetrics(data.summary);
        if (visualizer) {
            visualizer.render(data.nodes || [], data.links || []);
        }
    } catch (err) {
        console.error("Error loading graph network:", err);
    }
}

function updateMetrics(summary) {
    if (!summary) return;
    const suspects = summary.suspect_count ?? summary.total_suspects ?? 0;
    const accounts = summary.bank_account_count ?? summary.total_bank_accounts ?? 0;
    const phones = summary.phone_count ?? summary.total_phones ?? 0;
    const vehicles = summary.vehicle_count ?? summary.total_vehicles ?? 0;
    const firs = summary.fir_count ?? summary.total_firs ?? 0;
    const threats = summary.threat_alert_count ?? summary.active_threat_alerts ?? 0;
    const vol = summary.total_fraud_volume ?? summary.total_fraud_volume_traced ?? 0;

    const elSuspects = document.getElementById("stat-suspects");
    if (elSuspects) elSuspects.innerText = suspects;
    const elAccounts = document.getElementById("stat-accounts");
    if (elAccounts) elAccounts.innerText = accounts;
    const elPhones = document.getElementById("stat-phones");
    if (elPhones) elPhones.innerText = phones;
    const elVehicles = document.getElementById("stat-vehicles");
    if (elVehicles) elVehicles.innerText = vehicles;
    const elFirs = document.getElementById("stat-firs");
    if (elFirs) elFirs.innerText = firs;
    const elThreats = document.getElementById("stat-threats");
    if (elThreats) elThreats.innerText = threats;
    const navThreatEl = document.getElementById("nav-threat-count");
    if (navThreatEl) navThreatEl.innerText = threats;
    const elVol = document.getElementById("stat-fraud-volume");
    if (elVol) elVol.innerText = vol >= 10000000 ? `₹${(vol/10000000).toFixed(2)}Cr` : `₹${(vol/100000).toFixed(1)}L`;
}

async function checkHealth() {
    try {
        const res = await fetch(`${API_BASE}/api/health`);
        const data = await res.json();
        const pill = document.getElementById("neo4j-status-pill");
        const text = document.getElementById("neo4j-status-text");
        const dot = pill.querySelector(".status-dot");

        if (data.database === "neo4j") {
            dot.className = "status-dot online";
            text.innerText = "Neo4j Online";
        } else {
            dot.className = "status-dot online";
            text.innerText = "In-Memory ML Engine";
        }
    } catch (e) {
        const pill = document.getElementById("neo4j-status-pill");
        const text = document.getElementById("neo4j-status-text");
        const dot = pill.querySelector(".status-dot");
        dot.className = "status-dot offline";
        text.innerText = "Offline";
    }
}

// ==========================================
// TAB 5 & 6: THREAT & BSA CONTROLLERS
// ==========================================
async function loadFullBSARegistry() {
    const tbody = document.getElementById("bsa-full-registry-tbody");
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-secondary">Loading cryptographic evidence registry...</td></tr>`;

    try {
        const res = await fetch(`${API_BASE}/api/bsa-certificate/list`);
        if (!res.ok) throw new Error("Failed to load BSA evidence registry");
        const data = await res.json();
        const list = data.evidence_registry || [];

        if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center text-secondary py-3">No cryptographic records registered yet.</td></tr>`;
            return;
        }

        let html = "";
        list.forEach(r => {
            html += `
                <tr>
                    <td class="text-light fw-bold">${escapeHtml(r.label)}</td>
                    <td class="text-info tiny-text">${r.sha256_hash}</td>
                    <td class="text-secondary tiny-text">${escapeHtml(r.timestamp)}</td>
                    <td class="text-end">
                        <a href="${API_BASE}/api/bsa-certificate/download?sha256_hash=${encodeURIComponent(r.sha256_hash)}&case_reference=${encodeURIComponent(r.label)}" class="btn btn-xs btn-outline-info" target="_blank">
                            <i class="bi bi-file-earmark-pdf me-1"></i>Download PDF
                        </a>
                    </td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-danger py-3">Error loading registry: ${escapeHtml(e.message)}</td></tr>`;
    }
}

async function loadThreatCenter() {
    try {
        const res = await fetch(`${API_BASE}/api/threats`);
        if (!res.ok) return;
        const data = await res.json();
        
        // Update SIM churn container
        const churnContainer = document.getElementById("threat-simchurn-container");
        if (churnContainer && data.sim_churn_threats && data.sim_churn_threats.length > 0) {
            let churnHtml = `<p class="text-secondary tiny-text">Bipartite matching detected ${data.sim_churn_threats.length} SIM switch events:</p>`;
            data.sim_churn_threats.forEach(item => {
                churnHtml += `
                    <div class="p-2.5 rounded bg-dark border border-danger-subtle mb-2">
                        <div class="fw-bold text-light">${escapeHtml(item.deactivated_phone)} &rarr; ${escapeHtml(item.new_phone)}</div>
                        <div class="text-danger fw-bold tiny-text">${item.match_percentage}% Target Overlap (${item.matching_targets_count} contacts)</div>
                        <button class="btn btn-xs btn-outline-danger w-100 mt-2" onclick="switchView('graph'); visualizer.focusOnNode('${escapeHtml(item.new_phone)}');">
                            <i class="bi bi-diagram-3 me-1"></i>Inspect On Graph
                        </button>
                    </div>
                `;
            });
            churnContainer.innerHTML = churnHtml;
        }

        // Update BTS container
        const btsContainer = document.getElementById("threat-bts-container");
        if (btsContainer && data.bts_co_locations && data.bts_co_locations.length > 0) {
            let btsHtml = `<p class="text-secondary tiny-text">Found ${data.bts_co_locations.length} cell tower co-location pings within 10m window:</p>`;
            data.bts_co_locations.slice(0, 3).forEach(item => {
                btsHtml += `
                    <div class="p-2.5 rounded bg-dark border border-info-subtle mb-2">
                        <div class="fw-bold text-light">Tower: ${escapeHtml(item.tower_id)}</div>
                        <div class="text-info fw-bold tiny-text">Delta: ${item.time_delta_minutes.toFixed(1)}m (${escapeHtml(item.phone_a)} & ${escapeHtml(item.phone_b)})</div>
                        <button class="btn btn-xs btn-outline-info w-100 mt-2" onclick="switchView('graph'); visualizer.focusOnNode('${escapeHtml(item.phone_a)}');">
                            <i class="bi bi-diagram-3 me-1"></i>Inspect On Graph
                        </button>
                    </div>
                `;
            });
            btsContainer.innerHTML = btsHtml;
        }
    } catch (err) {
        console.error("Error loading threat center feed:", err);
    }
}

function bindUIEvents() {
    // Age Suspect Select Listener
    document.getElementById("select-age-suspect")?.addEventListener("change", updateAgeSuspectProfiler);

    // Syndicate Cluster Quick Isolation Filter
    document.querySelectorAll("#syndicate-filter-buttons button").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("#syndicate-filter-buttons button").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            const syn = btn.getAttribute("data-syndicate");
            filterGraphBySyndicate(syn);
        });
    });

    // Layout Mode Switcher (Clustered Islands vs Hierarchy Tree vs Force)
    document.querySelectorAll("#layout-mode-group button").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("#layout-mode-group button").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            const mode = btn.getAttribute("data-layout");
            if (visualizer) {
                visualizer.setLayoutMode(mode);
            }
        });
    });

    // Crime Story Walkthrough Controller
    initCrimeStoryPlayer();

    // Type Filter Buttons
    document.querySelectorAll("#filter-type-buttons button").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("#filter-type-buttons button").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            activeFilter = btn.getAttribute("data-filter");
            loadGraph();
        });
    });

    // Threats Only Switch
    const threatsSwitch = document.getElementById("switch-threats-only");
    if (threatsSwitch) {
        threatsSwitch.addEventListener("change", (e) => {
            threatsOnlyFilter = e.target.checked;
            loadGraph();
        });
    }

    // Risk Slider
    const slider = document.getElementById("risk-slider");
    const sliderBadge = document.getElementById("risk-val-badge");
    if (slider) {
        slider.addEventListener("input", (e) => {
            minRiskThreshold = parseFloat(e.target.value);
            if (sliderBadge) sliderBadge.innerText = minRiskThreshold.toFixed(2);
            loadGraph();
        });
    }

    // Zoom Controls
    document.getElementById("btn-zoom-in")?.addEventListener("click", () => visualizer?.zoomBy(1.3));
    document.getElementById("btn-zoom-out")?.addEventListener("click", () => visualizer?.zoomBy(0.7));
    document.getElementById("btn-zoom-reset")?.addEventListener("click", () => visualizer?.resetZoom());

    // Close sidepanel
    document.getElementById("btn-close-sidepanel")?.addEventListener("click", () => {
        visualizer?.clearSelection();
        handleNodeSelection(null);
    });

    // Reload Graph
    document.getElementById("btn-reload-graph")?.addEventListener("click", () => {
        loadGraph();
        loadThreatCenter();
    });

    // Recompute PageRank / Centrality
    document.getElementById("btn-run-pagerank")?.addEventListener("click", async () => {
        const btn = document.getElementById("btn-run-pagerank");
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm"></span> Computing...`;
        try {
            const res = await fetch(`${API_BASE}/api/algorithms/recompute`);
            const data = await res.json();
            alert(`Algorithms Executed:\n• Betweenness Centrality computed (${data.nodes_scored} nodes)\n• Active Threat Alerts: ${data.threat_alerts}`);
            await loadGraph();
            await loadThreatCenter();
        } catch (e) {
            alert(`Error: ${e.message}`);
        } finally {
            btn.disabled = false;
            btn.innerHTML = `<i class="bi bi-cpu me-1"></i> Recompute ML`;
        }
    });

    // Search Autocomplete & Instant Fly-To Engine
    const searchInput = document.getElementById("search-input");
    const searchDropdown = document.getElementById("search-results-dropdown");
    const clearBtn = document.getElementById("btn-search-clear");
    const searchGoBtn = document.getElementById("btn-search-go");

    function getSearchMatches(q) {
        const nodes = (currentGraphData && currentGraphData.nodes && currentGraphData.nodes.length > 0) 
            ? currentGraphData.nodes 
            : (visualizer ? visualizer.nodesData : []);

        if (!q || nodes.length === 0) return [];

        return nodes.filter(n => {
            const label = (n.label || "").toLowerCase();
            const id = (n.id || "").toLowerCase();
            const aliases = (n.details && n.details.aliases || []).map(a => a.toLowerCase());
            const veh = ((n.details && n.details.vehicle_registration) || "").toLowerCase();
            const acc = ((n.details && n.details.account_number) || "").toLowerCase();
            const phone = ((n.details && n.details.phone_number) || "").toLowerCase();

            return label.includes(q) || id.includes(q) || aliases.some(a => a.includes(q)) ||
                   veh.includes(q) || acc.includes(q) || phone.includes(q);
        }).slice(0, 10);
    }

    function selectAndFocusNode(nodeId, labelText) {
        if (!nodeId) return;
        if (searchDropdown) searchDropdown.classList.add("d-none");
        if (searchInput && labelText) searchInput.value = labelText;
        switchView("graph");
        if (visualizer) {
            visualizer.focusOnNode(nodeId);
        }
    }

    if (searchInput) {
        // Live typing autocomplete
        searchInput.addEventListener("input", (e) => {
            const q = e.target.value.toLowerCase().trim();
            if (!q) {
                searchDropdown?.classList.add("d-none");
                return;
            }

            const matches = getSearchMatches(q);

            if (matches.length === 0) {
                searchDropdown.innerHTML = `<div class="p-2 text-secondary tiny-text text-center">No matching entities found for "${escapeHtml(q)}"</div>`;
                searchDropdown.classList.remove("d-none");
                return;
            }

            searchDropdown.innerHTML = matches.map(m => {
                const riskBadge = m.risk_score >= 0.70 ? '<span class="badge text-bg-danger ms-1 tiny-text">High Risk</span>' : '';
                return `
                    <a href="#" class="dropdown-item d-flex justify-content-between align-items-center py-1.5 px-2 text-truncate" data-id="${escapeHtml(m.id)}" data-label="${escapeHtml(m.label)}">
                        <div class="text-truncate" style="max-width: 180px;">
                            <span class="badge bg-secondary tiny-text me-1">${escapeHtml(m.type)}</span>
                            <strong class="text-light small">${escapeHtml(m.label)}</strong>
                            ${riskBadge}
                        </div>
                        <span class="tiny-text font-mono text-secondary ms-1">${escapeHtml(m.id.split(':')[0])}</span>
                    </a>
                `;
            }).join("");
            searchDropdown.classList.remove("d-none");

            searchDropdown.querySelectorAll(".dropdown-item").forEach(item => {
                item.addEventListener("click", (evt) => {
                    evt.preventDefault();
                    const nodeId = item.getAttribute("data-id");
                    const labelText = item.getAttribute("data-label");
                    selectAndFocusNode(nodeId, labelText);
                });
            });
        });

        // Enter key to immediately jump to 1st match
        searchInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                const q = searchInput.value.toLowerCase().trim();
                if (!q) return;
                const matches = getSearchMatches(q);
                if (matches.length > 0) {
                    selectAndFocusNode(matches[0].id, matches[0].label);
                } else {
                    selectAndFocusNode(q, q);
                }
            } else if (e.key === "Escape") {
                searchDropdown?.classList.add("d-none");
            }
        });

        // Search Go Button
        searchGoBtn?.addEventListener("click", () => {
            const q = searchInput.value.toLowerCase().trim();
            if (!q) return;
            const matches = getSearchMatches(q);
            if (matches.length > 0) {
                selectAndFocusNode(matches[0].id, matches[0].label);
            } else {
                selectAndFocusNode(q, q);
            }
        });

        // Clear Search Button
        clearBtn?.addEventListener("click", () => {
            searchInput.value = "";
            searchDropdown?.classList.add("d-none");
            visualizer?.clearSelection();
            visualizer?.clearHighlight();
            handleNodeSelection(null);
        });

        // Click outside closes dropdown
        document.addEventListener("click", (evt) => {
            if (!searchInput.contains(evt.target) && !searchDropdown?.contains(evt.target)) {
                searchDropdown?.classList.add("d-none");
            }
        });
    }

    // Template Buttons in Ingestion Hub
    document.getElementById("btn-template-crypto")?.addEventListener("click", () => populateTemplate("crypto"));
    document.getElementById("btn-template-phishing")?.addEventListener("click", () => populateTemplate("phishing"));
    document.getElementById("btn-template-hawala")?.addEventListener("click", () => populateTemplate("hawala"));

    // FIR Text Form Submission
    const ingestForm = document.getElementById("ingest-fir-form");
    if (ingestForm) {
        ingestForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const submitBtn = document.getElementById("btn-submit-fir");
            const alertBox = document.getElementById("ingest-alert");

            const firNumber = document.getElementById("fir-number-input").value.trim();
            const policeStation = document.getElementById("police-station-input").value.trim();
            const state = document.getElementById("state-input").value.trim();
            const text = document.getElementById("fir-text-input").value.trim();

            submitBtn.disabled = true;
            submitBtn.innerHTML = `<span class="spinner-border spinner-border-sm"></span> Calculating SHA-256 & Ingesting...`;
            alertBox.className = "alert d-none";

            try {
                const res = await fetch(`${API_BASE}/api/analyze-fir`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        fir_number: firNumber,
                        police_station: policeStation,
                        state: state,
                        text: text
                    })
                });

                if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.detail || "Ingestion failed");
                }

                const result = await res.json();
                alertBox.className = "alert alert-success py-2 px-3 small";
                alertBox.innerHTML = `
                    <strong>${escapeHtml(result.message)}</strong><br>
                    <span class="tiny-text font-mono">SHA-256 Digest: ${result.sha256_hash}</span>
                `;
                ingestForm.reset();
                await loadGraph();
                await loadThreatCenter();
                setTimeout(() => switchView("graph"), 2000);
            } catch (err) {
                alertBox.className = "alert alert-danger py-2 px-3 small";
                alertBox.innerText = `Error: ${err.message}`;
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerHTML = `<i class="bi bi-shield-check me-1"></i> Ingest & Cryptographically Seal Record`;
            }
        });
    }

    // Bulk File Upload Form Submission
    const uploadForm = document.getElementById("upload-file-form");
    if (uploadForm) {
        uploadForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const submitBtn = document.getElementById("btn-submit-upload");
            const alertBox = document.getElementById("upload-alert");
            const fileInput = document.getElementById("file-input-element");
            const fileType = document.getElementById("upload-file-type").value;

            if (!fileInput.files || fileInput.files.length === 0) {
                alertBox.className = "alert alert-warning py-2 px-3 small";
                alertBox.innerText = "Please select a file to upload.";
                return;
            }

            const file = fileInput.files[0];
            const reader = new FileReader();

            submitBtn.disabled = true;
            submitBtn.innerHTML = `<span class="spinner-border spinner-border-sm"></span> Hashing & Ingesting...`;
            alertBox.className = "alert d-none";

            reader.onload = async (event) => {
                const fileContent = event.target.result;
                const payload = {
                    filename: file.name,
                    file_type: fileType,
                    content: fileContent
                };

                try {
                    const res = await fetch(`${API_BASE}/api/upload/file`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(payload)
                    });
                    if (!res.ok) {
                        const errData = await res.json();
                        throw new Error(errData.detail || "File upload failed");
                    }
                    const result = await res.json();

                    alertBox.className = "alert alert-success py-2 px-3 small";
                    alertBox.innerHTML = `
                        <strong>${escapeHtml(result.message)}</strong><br>
                        <span class="tiny-text font-mono">SHA-256: ${result.sha256_hash}</span>
                    `;
                    uploadForm.reset();
                    await loadGraph();
                    await loadThreatCenter();
                    setTimeout(() => switchView("graph"), 2000);
                } catch (err) {
                    alertBox.className = "alert alert-danger py-2 px-3 small";
                    alertBox.innerText = `Error: ${err.message}`;
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = `<i class="bi bi-cloud-arrow-up-fill me-1"></i> Upload, Hash & Ingest Dataset`;
                }
            };

            reader.onerror = () => {
                alertBox.className = "alert alert-danger py-2 px-3 small";
                alertBox.innerText = "Failed to read file.";
                submitBtn.disabled = false;
                submitBtn.innerHTML = `<i class="bi bi-cloud-arrow-up-fill me-1"></i> Upload, Hash & Ingest Dataset`;
            };

            reader.readAsText(file);
        });
    }
}

function populateTemplate(key) {
    const t = SAMPLE_FIRS[key];
    if (!t) return;
    document.getElementById("fir-number-input").value = t.fir_number;
    document.getElementById("police-station-input").value = t.police_station;
    document.getElementById("state-input").value = t.state;
    document.getElementById("fir-text-input").value = t.text;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert("SHA-256 Hash copied to clipboard:\n" + text);
    }).catch(err => {
        console.error("Copy failed:", err);
    });
}

window.focusScenario = function(type) {
    if (!visualizer) return;
    switchView("graph");
    
    setTimeout(() => {
        if (type === "sim_churn") {
            visualizer.focusOnNode("PHONE:9820099881");
        } else if (type === "vehicle") {
            visualizer.focusOnNode("VEHICLE:DL_01_AB_1234");
        } else if (type === "logistics") {
            visualizer.focusOnNode("ACCOUNT:440192837461");
        } else if (type === "bts") {
            visualizer.focusOnNode("PHONE:9810011223");
        } else if (type === "centrality") {
            const topNode = visualizer.nodesData
                .filter(n => n.centrality_score !== undefined)
                .sort((a, b) => (b.centrality_score || 0) - (a.centrality_score || 0))[0];
            if (topNode) {
                visualizer.focusOnNode(topNode.id);
            } else {
                visualizer.focusOnNode("SUSPECT:vikram_singhania");
            }
        }
    }, 100);
};

let activeBroadcastSuspectId = null;

window.triggerAPBBroadcast = function(suspectId) {
    activeBroadcastSuspectId = suspectId || null;

    // Reset stages
    document.getElementById("apb-setup-stage")?.classList.remove("d-none");
    document.getElementById("apb-results-stage")?.classList.add("d-none");

    // Populate Suspect Meta in Setup
    const nodes = (currentGraphData && currentGraphData.nodes) ? currentGraphData.nodes : [];
    let target = null;
    if (suspectId) {
        target = nodes.find(n => n.id === suspectId || n.label === suspectId);
    }
    if (!target) {
        target = nodes.find(n => n.type === "Suspect") || { label: "Vikram Singhania", id: "SUSPECT:vikram_singhania", details: {} };
    }

    const nameEl = document.getElementById("apb-config-suspect-name");
    const idEl = document.getElementById("apb-config-suspect-id");
    const aliasesEl = document.getElementById("apb-config-aliases");
    const vehEl = document.getElementById("apb-config-vehicles");

    if (nameEl) nameEl.innerText = target.label || "Vikram Singhania";
    if (idEl) idEl.innerText = target.id || "SUSPECT:vikram_singhania";
    
    const aliases = (target.details && target.details.aliases) || [target.label || "Vikram Singhania"];
    if (aliasesEl) aliasesEl.innerText = aliases.join(", ");
    
    const veh = (target.details && target.details.vehicle_registration) || "DL-01-AB-1234";
    if (vehEl) vehEl.innerText = veh;

    updateDispatchButtonCount();

    // Open Bootstrap Modal
    const modalEl = document.getElementById("apbBroadcastModal");
    if (!modalEl) return;
    const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    modal.show();
};

function updateDispatchButtonCount() {
    const checkedCount = document.querySelectorAll(".station-checkbox:checked").length;
    const btnText = document.getElementById("btn-dispatch-text");
    if (btnText) {
        btnText.innerText = `🚨 TRANSMIT INTELLIGENCE PACKET TO SELECTED (${checkedCount}) STATIONS`;
    }
}

// Station Quick Select Handlers
document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("btn-apb-select-all")?.addEventListener("click", () => {
        document.querySelectorAll(".station-checkbox").forEach(cb => cb.checked = true);
        updateDispatchButtonCount();
    });

    document.getElementById("btn-apb-select-metro")?.addEventListener("click", () => {
        const metros = ["delhi_special_cell", "mumbai_bkc", "bengaluru_stf", "kolkata_stf", "chennai_cyber"];
        document.querySelectorAll(".station-checkbox").forEach(cb => {
            cb.checked = metros.includes(cb.value);
        });
        updateDispatchButtonCount();
    });

    document.getElementById("btn-apb-clear-all")?.addEventListener("click", () => {
        document.querySelectorAll(".station-checkbox").forEach(cb => cb.checked = false);
        updateDispatchButtonCount();
    });

    document.querySelectorAll(".station-checkbox").forEach(cb => {
        cb.addEventListener("change", updateDispatchButtonCount);
    });

    document.getElementById("btn-apb-back-to-setup")?.addEventListener("click", () => {
        document.getElementById("apb-setup-stage")?.classList.remove("d-none");
        document.getElementById("apb-results-stage")?.classList.add("d-none");
    });

    // Execute Manual APB Dispatch Button
    document.getElementById("btn-execute-apb-dispatch")?.addEventListener("click", async () => {
        const selectedStationIds = Array.from(document.querySelectorAll(".station-checkbox:checked")).map(cb => cb.value);
        if (selectedStationIds.length === 0) {
            alert("Please select at least 1 destination police station.");
            return;
        }

        const priority = document.getElementById("apb-select-priority")?.value || "FLASH_RED_ALERT";
        const incVehicles = document.getElementById("apb-inc-vehicles")?.checked ?? true;
        const incAccounts = document.getElementById("apb-inc-accounts")?.checked ?? true;
        const incPhones = document.getElementById("apb-inc-phones")?.checked ?? true;

        const dispatchBtn = document.getElementById("btn-execute-apb-dispatch");
        dispatchBtn.disabled = true;
        dispatchBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> Transmitting Encrypted Payload...`;

        try {
            const payload = {
                suspect_id: activeBroadcastSuspectId,
                priority_level: priority,
                selected_stations: selectedStationIds,
                include_vehicles: incVehicles,
                include_bank_accounts: incAccounts,
                include_phones: incPhones,
                originating_officer: "Insp. R. K. Verma, Ingestion In-Charge",
                case_reference: "CR-2026-HQ-INTEL"
            };

            const res = await fetch(`${API_BASE}/api/broadcast/apb`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || "Dispatch failed");
            }

            const data = await res.json();

            // Transition to Results Stage
            document.getElementById("apb-setup-stage")?.classList.add("d-none");
            document.getElementById("apb-results-stage")?.classList.remove("d-none");

            document.getElementById("apb-status-title").innerText = `All-Points Bulletin Transmitted to ${data.dispatched_stations.length} Selected Police Stations!`;
            document.getElementById("apb-broadcast-id").innerText = data.broadcast_id;
            document.getElementById("apb-cctns-ref").innerText = `CCTNS National Gateway Ref: ${data.cctns_reference}`;
            document.getElementById("apb-sha256-seal").innerText = data.sha256_hash;

            // Set Certificate Link
            const certBtn = document.getElementById("apb-download-cert-btn");
            if (certBtn) {
                certBtn.href = `${API_BASE}/api/bsa-certificate/download?sha256_hash=${encodeURIComponent(data.sha256_hash)}&case_reference=${encodeURIComponent(data.broadcast_id)}`;
            }

            // Render Transmitted Police Stations
            let stationsHtml = "";
            (data.dispatched_stations || []).forEach(st => {
                stationsHtml += `
                    <tr>
                        <td class="text-light fw-bold"><i class="bi bi-shield-check text-success me-1.5"></i>${escapeHtml(st.station_name)}</td>
                        <td class="text-secondary">${escapeHtml(st.state)}</td>
                        <td><span class="badge text-bg-success font-mono tiny-text">${escapeHtml(st.status)}</span></td>
                        <td class="text-end text-info font-mono">${st.latency_ms}ms</td>
                    </tr>
                `;
            });
            document.getElementById("apb-stations-tbody").innerHTML = stationsHtml;
            document.getElementById("apb-dispatch-count").innerText = `${data.dispatched_stations.length}/${data.dispatched_stations.length} Acknowledged`;

        } catch (e) {
            alert(`Error transmitting APB: ${e.message}`);
        } finally {
            dispatchBtn.disabled = false;
            dispatchBtn.innerHTML = `<i class="bi bi-broadcast fs-5"></i><span id="btn-dispatch-text">🚨 TRANSMIT INTELLIGENCE PACKET TO SELECTED STATIONS</span>`;
            updateDispatchButtonCount();
        }
    });
});

// Crime Story Guided Walkthrough Data & Controller
const CRIME_STORY_STEPS = [
    {
        step: 1,
        title: "1. FIR Intercept: Extortion & Cyber Heist",
        tag: "DELHI SPECIAL CELL",
        tagClass: "text-bg-danger",
        desc: "FIR-2026-DEL-101 registered at Special Cell against an interstate syndicate coordinating corporate extortion and illegal bank transfers.",
        targetId: "FIR:FIR-2026-DEL-101",
        linkTypes: ["MENTIONED_IN", "INVOLVED_IN"]
    },
    {
        step: 2,
        title: "2. Syndicate Kingpin Identified",
        tag: "CRIMINAL BROKER",
        tagClass: "text-bg-warning text-dark",
        desc: "Graph Centrality analysis flags Vikram Singhania (alias Vikram Singhaniya) as highest betweenness broker coordinating across cells.",
        targetId: "SUSPECT:vikram_singhania",
        linkTypes: ["ACCOMPLICE_OF", "OPERATES_VEHICLE"]
    },
    {
        step: 3,
        title: "3. Getaway Vehicle Intercepted",
        tag: "CAR REGISTRATION",
        tagClass: "text-bg-purple",
        desc: "Vehicle DL-01-AB-1234 intercepted operating in Rohini, ferrying co-accused Amit Verma and cash courier Priya Sharma.",
        targetId: "VEHICLE:DL_01_AB_1234",
        linkTypes: ["OPERATES_VEHICLE"]
    },
    {
        step: 4,
        title: "4. Laundering Layer: ₹28,00,000 Mule Account",
        tag: "FROZEN BANK ACCOUNT",
        tagClass: "text-bg-warning text-dark",
        desc: "Forensic banking logs reveal ₹28 Lakhs wired to ICICI mule account 918234509122 before rapid ATM cash out.",
        targetId: "ACCOUNT:918234509122",
        linkTypes: ["TRANSFERRED_TO", "HOLDS_ACCOUNT"]
    },
    {
        step: 5,
        title: "5. Cell Tower BTS Co-Location (Delta 3.6m)",
        tag: "PHYSICAL CO-LOCATION",
        tagClass: "text-bg-info",
        desc: "Telecom CDR logs prove mobile numbers 9810011223 & 9811099887 pinged TOWER-DEL-402 within 3.6 minutes during the crime execution.",
        targetId: "PHONE:9810011223",
        linkTypes: ["CO_LOCATED", "CALLED"]
    }
];

let currentStoryStepIndex = 0;
let storyAutoInterval = null;

function initCrimeStoryPlayer() {
    const storyPanel = document.getElementById("crime-story-panel");
    const toggleBtn = document.getElementById("btn-toggle-story");
    const prevBtn = document.getElementById("btn-story-prev");
    const nextBtn = document.getElementById("btn-story-next");
    const autoBtn = document.getElementById("btn-story-auto");
    const closeBtn = document.getElementById("btn-story-close");

    function renderStoryStep(index) {
        if (!CRIME_STORY_STEPS[index]) return;
        currentStoryStepIndex = index;
        const step = CRIME_STORY_STEPS[index];

        document.getElementById("story-step-indicator").innerText = `Step ${step.step}/${CRIME_STORY_STEPS.length}`;
        document.getElementById("story-step-title").innerText = step.title;
        const tagEl = document.getElementById("story-step-tag");
        tagEl.innerText = step.tag;
        tagEl.className = `badge ${step.tagClass} tiny-text font-mono`;
        document.getElementById("story-step-desc").innerText = step.desc;

        if (visualizer) {
            visualizer.playStoryStep(step);
        }
    }

    toggleBtn?.addEventListener("click", () => {
        if (storyPanel.classList.contains("d-none")) {
            storyPanel.classList.remove("d-none");
            renderStoryStep(0);
        } else {
            storyPanel.classList.add("d-none");
            if (storyAutoInterval) clearInterval(storyAutoInterval);
        }
    });

    nextBtn?.addEventListener("click", () => {
        const nextIdx = (currentStoryStepIndex + 1) % CRIME_STORY_STEPS.length;
        renderStoryStep(nextIdx);
    });

    prevBtn?.addEventListener("click", () => {
        const prevIdx = (currentStoryStepIndex - 1 + CRIME_STORY_STEPS.length) % CRIME_STORY_STEPS.length;
        renderStoryStep(prevIdx);
    });

    autoBtn?.addEventListener("click", () => {
        if (storyAutoInterval) {
            clearInterval(storyAutoInterval);
            storyAutoInterval = null;
            autoBtn.innerHTML = `<i class="bi bi-play-fill me-1"></i>Auto Tour`;
            autoBtn.className = "btn btn-xs btn-outline-warning";
        } else {
            autoBtn.innerHTML = `<i class="bi bi-pause-fill me-1"></i>Pause Tour`;
            autoBtn.className = "btn btn-xs btn-warning text-dark";
            storyAutoInterval = setInterval(() => {
                const nextIdx = (currentStoryStepIndex + 1) % CRIME_STORY_STEPS.length;
                renderStoryStep(nextIdx);
            }, 4500);
        }
    });

    closeBtn?.addEventListener("click", () => {
        storyPanel.classList.add("d-none");
        if (storyAutoInterval) clearInterval(storyAutoInterval);
    });

    // Initialize first step on load
    renderStoryStep(0);
}

function filterGraphBySyndicate(syndicateKey) {
    if (!currentGraphData || !currentGraphData.nodes || !visualizer) return;

    if (!syndicateKey || syndicateKey === "ALL") {
        visualizer.clearHighlight();
        visualizer.render(currentGraphData.nodes, currentGraphData.links);
        return;
    }

    const filteredNodes = currentGraphData.nodes.filter(n => {
        const cluster = visualizer.getNodeCluster(n);
        return cluster === syndicateKey;
    });

    const nodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredLinks = currentGraphData.links.filter(l => {
        const src = typeof l.source === "object" ? l.source.id : l.source;
        const tgt = typeof l.target === "object" ? l.target.id : l.target;
        return nodeIds.has(src) && nodeIds.has(tgt);
    });

    visualizer.render(filteredNodes, filteredLinks);
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
