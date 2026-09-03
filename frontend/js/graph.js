/**
 * NEXUS GRAPH // D3.js v7 Precision Force & Syndicate Cluster Visualizer
 * Features:
 * - Canvas Background: Strictly Sky Blue (#87CEEB)
 * - 4 Syndicate Bubble Enclosures: Delhi BEC, Mumbai Logistics, Bengaluru Doxxers, Kolkata Hawala
 * - 3 Layout Modes: Clustered Islands, Crime Hierarchy (Top-Down), Organic Force
 * - High-Contrast Dark Pill Capsules for all Node & Edge labels (100% legibility)
 * - Dynamic Node Radius: Scaled by nx.betweenness_centrality
 * - Interactive Crime Story Narrator: Guided investigation step-by-step playback with glowing links
 */

class ForensicGraphVisualizer {
    constructor(svgSelector, onNodeSelectCallback) {
        this.svg = d3.select(svgSelector);
        this.onNodeSelect = onNodeSelectCallback;
        this.width = 0;
        this.height = 0;
        this.simulation = null;
        this.zoom = null;
        this.gContainer = null;
        this.hullGroup = null;
        this.linkGroup = null;
        this.linkTextGroup = null;
        this.nodeGroup = null;
        this.nodesData = [];
        this.linksData = [];
        this.selectedNodeId = null;
        this.currentLayoutMode = "cluster"; // 'cluster' | 'hierarchy' | 'force'
        this.tooltip = d3.select("#graph-tooltip");

        // Color mapping per entity type
        this.typeColors = {
            "Suspect": "#ef4444",      // Vibrant Crimson Red
            "BankAccount": "#f59e0b",  // Warm Amber / Gold
            "Location": "#10b981",     // Emerald Green
            "FIR": "#0284c7",          // Deep Ocean Blue
            "Phone": "#3b82f6",        // Royal Blue
            "Vehicle": "#8b5cf6",      // Vivid Purple
            "Organization": "#64748b"  // Slate
        };

        // Node badge icons
        this.typeBadges = {
            "Suspect": "👤",
            "BankAccount": "💳",
            "Location": "📍",
            "FIR": "📜",
            "Phone": "📱",
            "Vehicle": "🚗",
            "Organization": "🏢"
        };

        // Syndicate Cluster Definitions & Colors
        this.syndicates = {
            "delhi": {
                name: "Delhi BEC & Extortion Syndicate",
                color: "#ef4444",
                quadrant: { xRatio: 0.28, yRatio: 0.28 }
            },
            "mumbai": {
                name: "Mumbai Trafficking & Mule Ring",
                color: "#f59e0b",
                quadrant: { xRatio: 0.72, yRatio: 0.28 }
            },
            "bengaluru": {
                name: "Bengaluru Loan App Doxxers",
                color: "#10b981",
                quadrant: { xRatio: 0.28, yRatio: 0.72 }
            },
            "kolkata": {
                name: "Kolkata Hawala Nexus",
                color: "#8b5cf6",
                quadrant: { xRatio: 0.72, yRatio: 0.72 }
            }
        };

        // Dynamic radius scale based on centrality_score
        this.centralityRadiusScale = d3.scaleLinear()
            .domain([0, 0.4])
            .range([14, 38])
            .clamp(true);

        this.init();
    }

    getNodeRadius(d) {
        const score = parseFloat(d.centrality_score || (d.details && d.details.centrality_score) || 0.0);
        return this.centralityRadiusScale(score);
    }

    // Determine cluster for any given node
    getNodeCluster(d) {
        const id = (d.id || "").toLowerCase();
        const label = (d.label || "").toLowerCase();
        const loc = ((d.details && d.details.location) || "").toLowerCase();
        const veh = ((d.details && d.details.vehicle_registration) || "").toLowerCase();

        if (id.includes("del") || label.includes("delhi") || label.includes("vikram") || label.includes("amit") || label.includes("priya") || veh.includes("dl-") || loc.includes("delhi")) {
            return "delhi";
        }
        if (id.includes("mum") || label.includes("mumbai") || label.includes("tariq") || label.includes("sameer") || veh.includes("mh-") || loc.includes("mumbai")) {
            return "mumbai";
        }
        if (id.includes("blr") || label.includes("bengaluru") || label.includes("rahul") || label.includes("dinesh") || veh.includes("ka-") || loc.includes("bengaluru")) {
            return "bengaluru";
        }
        if (id.includes("kol") || label.includes("kolkata") || label.includes("kabir") || label.includes("farhan") || label.includes("ananya") || veh.includes("wb-") || loc.includes("kolkata")) {
            return "kolkata";
        }

        // Fallback distribution
        if (d.type === "BankAccount") return "delhi";
        if (d.type === "Phone") return "mumbai";
        return "delhi";
    }

    init() {
        const bbox = this.svg.node()?.parentElement?.getBoundingClientRect() || {};
        this.width = bbox.width || (window.innerWidth > 600 ? window.innerWidth - 320 : 800);
        this.height = bbox.height || (window.innerHeight > 400 ? window.innerHeight - 90 : 600);

        this.svg.selectAll("*").remove();
        this.svg.attr("style", "background-color: #87CEEB !important; background: #87CEEB !important;");

        // Arrowhead Marker Definitions
        const defs = this.svg.append("defs");
        
        defs.append("marker")
            .attr("id", "arrow-default")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 26)
            .attr("refY", 0)
            .attr("markerWidth", 6.5)
            .attr("markerHeight", 6.5)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-4L10,0L0,4")
            .attr("fill", "#0f172a");

        defs.append("marker")
            .attr("id", "arrow-transfer")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 30)
            .attr("refY", 0)
            .attr("markerWidth", 7.5)
            .attr("markerHeight", 7.5)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-4L10,0L0,4")
            .attr("fill", "#b45309");

        defs.append("marker")
            .attr("id", "arrow-simchurn")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 30)
            .attr("refY", 0)
            .attr("markerWidth", 8)
            .attr("markerHeight", 8)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-4L10,0L0,4")
            .attr("fill", "#0284c7");

        // SVG Root Container for zoom/pan
        this.gContainer = this.svg.append("g").attr("class", "graph-root");
        this.hullGroup = this.gContainer.append("g").attr("class", "hulls-layer");
        this.linkGroup = this.gContainer.append("g").attr("class", "links-layer");
        this.linkTextGroup = this.gContainer.append("g").attr("class", "link-labels-layer");
        this.nodeGroup = this.gContainer.append("g").attr("class", "nodes-layer");

        // D3 Zoom & Pan
        this.zoom = d3.zoom()
            .scaleExtent([0.15, 4.5])
            .on("zoom", (event) => {
                this.gContainer.attr("transform", event.transform);
            });

        this.svg.call(this.zoom);

        window.addEventListener("resize", () => this.handleResize());
    }

    handleResize() {
        const bbox = this.svg.node()?.parentElement?.getBoundingClientRect() || {};
        if (bbox.width && bbox.width > 50) {
            this.width = bbox.width;
            this.height = bbox.height || (window.innerHeight - 90);
        }
        if (this.simulation) {
            this.updateSimulationForces();
            this.simulation.alpha(0.3).restart();
        }
    }

    setLayoutMode(mode) {
        this.currentLayoutMode = mode;
        if (!this.simulation) return;

        this.updateSimulationForces();
        this.simulation.alpha(0.8).restart();

        // Toggle hull visibility
        if (this.hullGroup) {
            this.hullGroup.style("display", mode === "cluster" ? "block" : "none");
        }
    }

    updateSimulationForces() {
        if (!this.simulation) return;

        const w = this.width;
        const h = this.height;

        if (this.currentLayoutMode === "cluster") {
            // Clustered Island Layout: Pull nodes toward their regional syndicate quadrant centers
            this.simulation
                .force("center", null)
                .force("clusterX", d3.forceX(d => {
                    const c = this.syndicates[d.cluster] || this.syndicates.delhi;
                    return w * c.quadrant.xRatio;
                }).strength(0.35))
                .force("clusterY", d3.forceY(d => {
                    const c = this.syndicates[d.cluster] || this.syndicates.delhi;
                    return h * c.quadrant.yRatio;
                }).strength(0.35))
                .force("charge", d3.forceManyBody().strength(-380).distanceMax(500))
                .force("collision", d3.forceCollide().radius(d => this.getNodeRadius(d) + 26));

        } else if (this.currentLayoutMode === "hierarchy") {
            // Crime Hierarchy Layout: Kingpins on top, operatives middle, bank accounts bottom
            this.simulation
                .force("center", d3.forceCenter(w / 2, h / 2).strength(0.1))
                .force("clusterX", d3.forceX(w / 2).strength(0.08))
                .force("clusterY", d3.forceY(d => {
                    if (d.type === "Suspect") return h * 0.22;
                    if (d.type === "Phone" || d.type === "Vehicle") return h * 0.50;
                    if (d.type === "BankAccount" || d.type === "Location" || d.type === "FIR") return h * 0.78;
                    return h * 0.50;
                }).strength(0.55))
                .force("charge", d3.forceManyBody().strength(-480).distanceMax(650))
                .force("collision", d3.forceCollide().radius(d => this.getNodeRadius(d) + 28));

        } else {
            // Organic Force Network Layout
            this.simulation
                .force("center", d3.forceCenter(w / 2, h / 2).strength(0.2))
                .force("clusterX", null)
                .force("clusterY", null)
                .force("charge", d3.forceManyBody().strength(-550).distanceMax(750))
                .force("collision", d3.forceCollide().radius(d => this.getNodeRadius(d) + 24));
        }
    }

    render(nodes, links) {
        this.nodesData = nodes.map(d => {
            const node = { ...d };
            node.cluster = this.getNodeCluster(node);
            return node;
        });
        this.linksData = links.map(d => ({ ...d }));

        this.hullGroup.selectAll("*").remove();
        this.linkGroup.selectAll("*").remove();
        this.linkTextGroup.selectAll("*").remove();
        this.nodeGroup.selectAll("*").remove();

        if (this.nodesData.length === 0) return;

        const bbox = this.svg.node()?.parentElement?.getBoundingClientRect() || {};
        if (bbox.width && bbox.width > 50) {
            this.width = bbox.width;
            this.height = bbox.height || (window.innerHeight - 90);
        }

        const maxCentrality = d3.max(this.nodesData, d => parseFloat(d.centrality_score || 0)) || 0.2;
        this.centralityRadiusScale.domain([0, Math.max(maxCentrality, 0.05)]);

        // 1. Initialize Simulation
        this.simulation = d3.forceSimulation(this.nodesData)
            .force("link", d3.forceLink(this.linksData)
                .id(d => d.id)
                .distance(d => {
                    if (d.type === "TRANSFERRED_TO") return 140;
                    if (d.type === "CO_LOCATED") return 90;
                    if (d.type === "SIM_CHURN_CONTINUITY") return 110;
                    return 115;
                })
                .strength(0.65));

        this.updateSimulationForces();

        // 2. Render Links Layer
        const linkElements = this.linkGroup.selectAll("line")
            .data(this.linksData)
            .enter()
            .append("line")
            .attr("class", d => {
                let cls = "graph-link";
                if (d.type === "TRANSFERRED_TO") cls += " link-transfer";
                else if (d.type === "CO_LOCATED") cls += " link-colocated";
                else if (d.type === "SIM_CHURN_CONTINUITY") cls += " link-simchurn";
                return cls;
            })
            .attr("stroke", d => {
                if (d.type === "TRANSFERRED_TO") return "#b45309";
                if (d.type === "CO_LOCATED") return "#6d28d9";
                if (d.type === "SIM_CHURN_CONTINUITY") return "#0284c7";
                return "#1e293b";
            })
            .attr("stroke-width", d => {
                if (d.type === "SIM_CHURN_CONTINUITY") return 3.5;
                if (d.type === "CO_LOCATED") return 2.5;
                if (d.amount) return Math.min(Math.max(d.amount / 500000, 2.0), 5.5);
                return Math.max(d.weight || 1.0, 1.5);
            })
            .attr("stroke-dasharray", d => {
                if (d.type === "CO_LOCATED") return "4,3";
                if (d.type === "SIM_CHURN_CONTINUITY") return "6,2";
                if (d.type === "TRANSFERRED_TO") return "4,2";
                return null;
            })
            .attr("marker-end", d => {
                if (d.type === "TRANSFERRED_TO") return "url(#arrow-transfer)";
                if (d.type === "SIM_CHURN_CONTINUITY") return "url(#arrow-simchurn)";
                if (d.type === "CO_LOCATED") return null;
                return "url(#arrow-default)";
            });

        // 3. Render Link Labels with Background Pill Rectangles
        const linkLabelNodes = this.linksData.filter(d => d.amount || d.type === "TRANSFERRED_TO" || d.type === "CO_LOCATED" || d.type === "SIM_CHURN_CONTINUITY");
        
        const linkTextContainers = this.linkTextGroup.selectAll("g.link-label-container")
            .data(linkLabelNodes)
            .enter()
            .append("g")
            .attr("class", "link-label-container");

        linkTextContainers.append("rect")
            .attr("class", "link-label-rect")
            .attr("fill", "rgba(15, 23, 42, 0.92)")
            .attr("stroke", d => {
                if (d.type === "TRANSFERRED_TO") return "#f59e0b";
                if (d.type === "SIM_CHURN_CONTINUITY") return "#38bdf8";
                return "#64748b";
            })
            .attr("height", 16)
            .attr("rx", 3);

        linkTextContainers.append("text")
            .attr("class", "graph-link-label")
            .attr("text-anchor", "middle")
            .attr("dy", 11)
            .text(d => {
                if (d.amount) return `₹${(d.amount / 100000).toFixed(1)}L`;
                if (d.type === "CO_LOCATED") return `BTS:${d.details && d.details.tower_id ? d.details.tower_id.replace('TOWER-','') : 'CELL'}`;
                if (d.type === "SIM_CHURN_CONTINUITY") return "SIM CHURN (100%)";
                return d.type;
            });

        // Dynamically fit link label background rects
        linkTextContainers.each(function() {
            const g = d3.select(this);
            const textNode = g.select("text").node();
            if (textNode) {
                const textBBox = textNode.getBBox();
                g.select("rect")
                    .attr("x", textBBox.x - 4)
                    .attr("y", textBBox.y - 2)
                    .attr("width", textBBox.width + 8)
                    .attr("height", textBBox.height + 4);
            }
        });

        // 4. Render Nodes Layer
        const nodeElements = this.nodeGroup.selectAll("g.graph-node")
            .data(this.nodesData)
            .enter()
            .append("g")
            .attr("class", "graph-node")
            .attr("data-id", d => d.id)
            .call(this.dragBehavior());

        // Pulsing Threat Halo for High Risk Nodes
        nodeElements.filter(d => d.alert || (d.risk_score || 0) >= 0.70)
            .append("circle")
            .attr("class", "pulsing-ring")
            .attr("r", d => this.getNodeRadius(d) + 7)
            .attr("fill", "none")
            .attr("stroke", "#dc2626")
            .attr("stroke-width", 2.4);

        // Core Node Circle
        nodeElements.append("circle")
            .attr("class", "node-core")
            .attr("r", d => this.getNodeRadius(d))
            .attr("fill", d => this.typeColors[d.type] || "#64748b")
            .attr("stroke", "#0b0f19")
            .attr("stroke-width", 2.6);

        // Node Type Badge Character / Emoji
        nodeElements.append("text")
            .attr("class", "node-badge")
            .attr("text-anchor", "middle")
            .attr("dy", 3.8)
            .text(d => this.typeBadges[d.type] || "•");

        // Node Label with Dark Background Capsule
        const labelGroup = nodeElements.append("g").attr("class", "node-label-group");
        
        labelGroup.append("rect")
            .attr("class", "node-label-pill")
            .attr("height", 17)
            .attr("rx", 4);

        labelGroup.append("text")
            .attr("class", "node-label")
            .attr("text-anchor", "middle")
            .attr("dy", d => this.getNodeRadius(d) + 14)
            .text(d => {
                const name = d.label || d.id;
                if (name.length > 20) return name.substring(0, 18) + "...";
                return name;
            });

        // Fit label pill rect around text
        labelGroup.each(function(d) {
            const g = d3.select(this);
            const textNode = g.select("text").node();
            if (textNode) {
                const b = textNode.getBBox();
                g.select("rect")
                    .attr("x", b.x - 5)
                    .attr("y", b.y - 1)
                    .attr("width", b.width + 10)
                    .attr("height", b.height + 2);
            }
        });

        // 5. Tooltips & Selection Listeners
        nodeElements.on("mouseenter", (event, d) => {
            this.highlightNeighborhood(d.id);
            this.showTooltip(event, d);
        });

        nodeElements.on("mousemove", (event) => {
            this.moveTooltip(event);
        });

        nodeElements.on("mouseleave", () => {
            this.clearHighlight();
            this.hideTooltip();
        });

        nodeElements.on("click", (event, d) => {
            event.stopPropagation();
            this.selectNode(d.id);
            this.highlightNeighborhood(d.id);
            if (this.onNodeSelect) {
                this.onNodeSelect(d);
            }
        });

        this.svg.on("click", () => {
            this.clearSelection();
            this.clearHighlight();
            if (this.onNodeSelect) {
                this.onNodeSelect(null);
            }
        });

        // 6. Simulation Tick Handler with Convex Hull Rendering
        this.simulation.on("tick", () => {
            // Update Links
            linkElements
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            // Update Link Labels
            linkTextContainers.attr("transform", d => {
                const x = (d.source.x + d.target.x) / 2;
                const y = (d.source.y + d.target.y) / 2;
                return `translate(${x}, ${y})`;
            });

            // Update Nodes
            nodeElements.attr("transform", d => `translate(${d.x}, ${d.y})`);

            // Update Syndicate Cluster Hulls
            if (this.currentLayoutMode === "cluster") {
                this.updateClusterHulls();
            }
        });
    }

    updateClusterHulls() {
        const clusterKeys = Object.keys(this.syndicates);
        const hullData = [];

        clusterKeys.forEach(key => {
            const clusterNodes = this.nodesData.filter(d => d.cluster === key);
            if (clusterNodes.length < 3) return;

            const points = [];
            clusterNodes.forEach(n => {
                const r = this.getNodeRadius(n) + 32;
                // Add bounding points around each node for smooth padding
                points.push([n.x - r, n.y - r]);
                points.push([n.x + r, n.y - r]);
                points.push([n.x + r, n.y + r]);
                points.push([n.x - r, n.y + r]);
            });

            const hull = d3.polygonHull(points);
            if (hull) {
                const centroid = d3.polygonCentroid(hull);
                hullData.push({
                    key: key,
                    hull: hull,
                    centroid: centroid,
                    info: this.syndicates[key]
                });
            }
        });

        // Render Hulls
        const hulls = this.hullGroup.selectAll("path.cluster-hull")
            .data(hullData, d => d.key);

        hulls.enter()
            .append("path")
            .attr("class", "cluster-hull")
            .merge(hulls)
            .attr("d", d => "M" + d.hull.join("L") + "Z")
            .attr("fill", d => d.info.color)
            .attr("stroke", d => d.info.color);

        hulls.exit().remove();

        // Render Hull Titles
        const titles = this.hullGroup.selectAll("g.cluster-title-group")
            .data(hullData, d => d.key);

        const titleEnter = titles.enter()
            .append("g")
            .attr("class", "cluster-title-group");

        titleEnter.append("rect")
            .attr("class", "cluster-title-pill")
            .attr("stroke", d => d.info.color);

        titleEnter.append("text")
            .attr("class", "cluster-title-text")
            .attr("text-anchor", "middle")
            .attr("dy", 13)
            .text(d => `⚡ ${d.info.name.toUpperCase()}`);

        const mergedTitles = titleEnter.merge(titles);
        mergedTitles.attr("transform", d => {
            // Find top-most point of the hull
            const minY = d3.min(d.hull, p => p[1]);
            return `translate(${d.centroid[0]}, ${minY - 12})`;
        });

        mergedTitles.each(function() {
            const g = d3.select(this);
            const textNode = g.select("text").node();
            if (textNode) {
                const b = textNode.getBBox();
                g.select("rect")
                    .attr("x", b.x - 8)
                    .attr("y", b.y - 2)
                    .attr("width", b.width + 16)
                    .attr("height", b.height + 4);
            }
        });

        titles.exit().remove();
    }

    showTooltip(event, d) {
        const riskScore = parseFloat(d.risk_score || 0);
        const riskPct = Math.round(riskScore * 100);
        const riskClass = riskPct >= 70 ? "text-danger" : (riskPct >= 40 ? "text-warning" : "text-success");
        const centrality = parseFloat(d.centrality_score || (d.details && d.details.centrality_score) || 0).toFixed(4);

        let html = `
            <div class="d-flex justify-content-between align-items-center mb-1">
                <span class="badge" style="background:${this.typeColors[d.type] || '#64748b'}; color:#ffffff;">${escapeHtml(d.type)}</span>
                <span class="font-mono fw-bold ${riskClass}">Risk: ${riskPct}%</span>
            </div>
            <div class="fw-bold text-light mb-1" style="font-size: 0.9rem;">${escapeHtml(d.label || d.id)}</div>
            <div class="tiny-text font-mono text-secondary mb-1">ID: ${escapeHtml(d.id)}</div>
            <div class="tiny-text text-secondary mb-1">
                <strong>Broker Centrality:</strong> <span class="text-info font-mono">${centrality}</span>
            </div>
        `;

        if (d.alert || (d.alert_reasons && d.alert_reasons.length > 0)) {
            html += `
                <div class="mt-1 pt-1 border-top border-danger-subtle text-danger tiny-text fw-bold">
                    ⚠️ Active Threat: ${(d.alert_reasons || ["Flagged Activity"])[0]}
                </div>
            `;
        }

        this.tooltip.html(html).style("display", "block");
        this.moveTooltip(event);
    }

    moveTooltip(event) {
        const containerRect = this.svg.node()?.parentElement?.getBoundingClientRect() || { left: 0, top: 0 };
        const x = event.clientX - containerRect.left + 15;
        const y = event.clientY - containerRect.top + 15;
        this.tooltip.style("left", `${x}px`).style("top", `${y}px`);
    }

    hideTooltip() {
        this.tooltip.style("display", "none");
    }

    dragBehavior() {
        return d3.drag()
            .on("start", (event, d) => {
                if (!event.active) this.simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            })
            .on("drag", (event, d) => {
                d.fx = event.x;
                d.fy = event.y;
            })
            .on("end", (event, d) => {
                if (!event.active) this.simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            });
    }

    selectNode(nodeId) {
        this.selectedNodeId = nodeId;
        this.gContainer.selectAll(".graph-node")
            .classed("selected", d => d.id === nodeId);
    }

    clearSelection() {
        this.selectedNodeId = null;
        this.gContainer.selectAll(".graph-node").classed("selected", false);
    }

    highlightNeighborhood(nodeId) {
        const connectedNodes = new Set([nodeId]);
        
        this.gContainer.selectAll(".graph-link")
            .classed("highlighted", l => {
                const srcId = typeof l.source === "object" ? l.source.id : l.source;
                const tgtId = typeof l.target === "object" ? l.target.id : l.target;
                if (srcId === nodeId || tgtId === nodeId) {
                    connectedNodes.add(srcId);
                    connectedNodes.add(tgtId);
                    return true;
                }
                return false;
            });

        this.gContainer.selectAll(".graph-node")
            .classed("dimmed", d => !connectedNodes.has(d.id));
    }

    clearHighlight() {
        this.gContainer.selectAll(".graph-link")
            .classed("highlighted", false)
            .classed("story-active", false);
        this.gContainer.selectAll(".graph-node").classed("dimmed", false);
    }

    focusOnNode(nodeId) {
        if (!nodeId || !this.nodesData || this.nodesData.length === 0) return;
        const q = String(nodeId).toLowerCase().trim();

        let target = this.nodesData.find(n => n.id === nodeId || (n.label && n.label.toLowerCase() === q) || n.id.toLowerCase() === q);
        if (!target) {
            target = this.nodesData.find(n => (n.label && n.label.toLowerCase().includes(q)) || n.id.toLowerCase().includes(q));
        }
        if (!target) {
            target = this.nodesData.find(n => {
                const aliases = (n.details && n.details.aliases) || [];
                const veh = (n.details && n.details.vehicle_registration) || "";
                const acc = (n.details && n.details.account_number) || "";
                const phone = (n.details && n.details.phone_number) || "";
                return aliases.some(a => a.toLowerCase().includes(q)) ||
                       veh.toLowerCase().includes(q) ||
                       acc.includes(q) ||
                       phone.includes(q);
            });
        }

        if (!target) {
            console.warn("Node not found for focus:", nodeId);
            return;
        }

        this.selectNode(target.id);
        this.highlightNeighborhood(target.id);
        if (this.onNodeSelect) {
            this.onNodeSelect(target);
        }

        const targetX = target.x !== undefined ? target.x : this.width / 2;
        const targetY = target.y !== undefined ? target.y : this.height / 2;

        const scale = 1.65;
        const x = this.width / 2 - targetX * scale;
        const y = this.height / 2 - targetY * scale;

        this.svg.transition()
            .duration(750)
            .call(
                this.zoom.transform,
                d3.zoomIdentity.translate(x, y).scale(scale)
            );
    }

    // Playback a specific crime story step
    playStoryStep(step) {
        if (!step) return;

        this.clearHighlight();

        const focusNode = this.nodesData.find(n => n.id === step.targetId || (n.label && n.label.toLowerCase().includes(step.targetId.toLowerCase())));
        if (!focusNode) return;

        this.selectNode(focusNode.id);
        if (this.onNodeSelect) {
            this.onNodeSelect(focusNode);
        }

        // Highlight story links
        if (step.linkTypes || step.connectedIds) {
            this.gContainer.selectAll(".graph-link")
                .classed("story-active", l => {
                    const srcId = typeof l.source === "object" ? l.source.id : l.source;
                    const tgtId = typeof l.target === "object" ? l.target.id : l.target;
                    const matchesNode = (srcId === focusNode.id || tgtId === focusNode.id);
                    const matchesType = !step.linkTypes || step.linkTypes.includes(l.type);
                    return matchesNode && matchesType;
                });
        }

        const scale = 1.75;
        const x = this.width / 2 - (focusNode.x || this.width/2) * scale;
        const y = this.height / 2 - (focusNode.y || this.height/2) * scale;

        this.svg.transition()
            .duration(800)
            .call(
                this.zoom.transform,
                d3.zoomIdentity.translate(x, y).scale(scale)
            );
    }

    resetZoom() {
        this.svg.transition()
            .duration(600)
            .call(this.zoom.transform, d3.zoomIdentity);
    }

    zoomBy(factor) {
        this.svg.transition()
            .duration(300)
            .call(this.zoom.scaleBy, factor);
    }
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
