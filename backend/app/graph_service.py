import logging
import datetime
import networkx as nx
from typing import Dict, List, Any, Optional, Set, Tuple
from app.database import db_manager
from app.models import Node, Link, GraphResponse, GraphSummary, NodeDetailResponse

logger = logging.getLogger("crime_intelligence.graph")

class GraphService:
    """
    Forensic Graph Engine:
    - Phase 2: In-memory NetworkX mapping & nx.betweenness_centrality() -> centrality_score
    - Phase 4: Threat Detection:
        1. SIM Churn (Bipartite Graph Matching >= 85% target overlap)
        2. Logistics Filter (Transit + High-frequency hotel bookings)
        3. BTS Co-Location (<= 10 min cell tower ping threshold)
    - Phase 5: JSON payload serialization for D3.js forceSimulation
    """
    def __init__(self):
        self.tower_pings_registry: List[Dict[str, Any]] = []
        self.financial_logs_registry: List[Dict[str, Any]] = []

    def register_tower_ping(self, phone_number: str, tower_id: str, timestamp_str: str):
        """Registers a BTS cell tower ping for co-location evaluation."""
        self.tower_pings_registry.append({
            "phone": phone_number,
            "tower_id": tower_id,
            "timestamp": timestamp_str
        })

    def register_financial_tx(self, account_or_suspect: str, category: str, merchant: str, amount: float, timestamp_str: str):
        """Registers financial transaction for logistics pattern filtering."""
        self.financial_logs_registry.append({
            "entity": account_or_suspect,
            "category": category.upper(),
            "merchant": merchant,
            "amount": amount,
            "timestamp": timestamp_str
        })

    def run_bts_colocation_engine(self) -> int:
        """
        Phase 4: BTS Co-Location Engine:
        Time-window grouping function: If two distinct phone nodes register pings
        to the identical cell tower ID within a 10-minute threshold (<= 600s),
        programmatically generates a new CO_LOCATED edge between them.
        """
        colocations_found = 0
        pings = self.tower_pings_registry
        if len(pings) < 2:
            return 0

        def parse_time(ts_str: str) -> Optional[datetime.datetime]:
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M",
                "%Y-%m-%d"
            ]
            for fmt in formats:
                try:
                    return datetime.datetime.strptime(ts_str.strip(), fmt)
                except Exception:
                    pass
            return None

        # Group pings by tower_id
        tower_groups: Dict[str, List[Dict[str, Any]]] = {}
        for p in pings:
            t_id = p["tower_id"]
            if t_id and t_id != "UNKNOWN":
                tower_groups.setdefault(t_id, []).append(p)

        created_edges = set()
        for t_id, t_pings in tower_groups.items():
            for i in range(len(t_pings)):
                for j in range(i + 1, len(t_pings)):
                    p1 = t_pings[i]
                    p2 = t_pings[j]
                    if p1["phone"] == p2["phone"]:
                        continue

                    t1 = parse_time(p1["timestamp"])
                    t2 = parse_time(p2["timestamp"])

                    delta_min = 0.0
                    if t1 and t2:
                        delta_sec = abs((t1 - t2).total_seconds())
                        delta_min = delta_sec / 60.0
                        if delta_sec > 600:  # > 10 minutes threshold
                            continue
                    
                    phone1_id = f"PHONE:{p1['phone']}" if not p1['phone'].startswith("PHONE:") else p1['phone']
                    phone2_id = f"PHONE:{p2['phone']}" if not p2['phone'].startswith("PHONE:") else p2['phone']
                    
                    edge_pair = tuple(sorted([phone1_id, phone2_id]))
                    if edge_pair in created_edges:
                        continue
                    created_edges.add(edge_pair)

                    db_manager.merge_relationship(
                        source_id=phone1_id,
                        target_id=phone2_id,
                        rel_type="CO_LOCATED",
                        properties={
                            "tower_id": t_id,
                            "time_delta_minutes": round(delta_min, 1),
                            "timestamp": p1["timestamp"],
                            "context": f"BTS Tower {t_id} Co-Location (within {round(delta_min, 1)}m window)",
                            "weight": 2.5
                        }
                    )
                    colocations_found += 1
                    logger.info(f"Generated BTS CO_LOCATED edge: {phone1_id} <-> {phone2_id} at {t_id} (Delta: {delta_min:.1f}m)")

        return colocations_found

    def run_sim_churn_detection(self, G: nx.DiGraph, nodes_dict: Dict[str, Dict[str, Any]]) -> int:
        """
        Phase 4: SIM Churn Detection via Bipartite Graph Matching:
        If a phone number node is deactivated, scan network for newly activated numbers
        whose outbound edge targets match the deactivated node's targets by at least 85% (>= 0.85).
        If matched, link with SIM_CHURN_CONTINUITY, mark suspect alert, and merge behavioral identity.
        """
        churn_matches = 0
        phone_nodes = [nid for nid, n in nodes_dict.items() if n.get("type") == "Phone"]
        
        deactivated_phones = []
        active_phones = []

        for pid in phone_nodes:
            props = nodes_dict[pid].get("details", {})
            status = props.get("status", "Active").lower()
            if "deactivat" in status or "dormant" in status or "churn" in status:
                deactivated_phones.append(pid)
            else:
                active_phones.append(pid)

        for d_id in deactivated_phones:
            d_targets = set(G.successors(d_id)) if G.has_node(d_id) else set()
            if not d_targets:
                continue

            for a_id in active_phones:
                if d_id == a_id:
                    continue
                a_targets = set(G.successors(a_id)) if G.has_node(a_id) else set()
                if not a_targets:
                    continue

                # Calculate Jaccard similarity / bipartite target overlap
                intersection = d_targets.intersection(a_targets)
                union = d_targets.union(a_targets)
                overlap_ratio = len(intersection) / len(union) if union else 0.0

                if overlap_ratio >= 0.85 or (len(intersection) >= 3 and len(intersection) / max(len(d_targets), 1) >= 0.85):
                    churn_matches += 1
                    pct_str = f"{int(overlap_ratio * 100)}%"
                    reason = f"SIM Churn Continuity: {pct_str} contact target overlap between {d_id} and {a_id}"
                    
                    # Update alerts
                    for pid in [d_id, a_id]:
                        n = nodes_dict[pid]
                        n["alert"] = True
                        n.setdefault("alert_reasons", [])
                        if reason not in n["alert_reasons"]:
                            n["alert_reasons"].append(reason)
                        n["details"]["alert"] = True
                        n["details"]["alert_reasons"] = n["alert_reasons"]
                        db_manager.merge_node(pid, n["label"], "Phone", n["details"])

                    # Create SIM_CHURN_CONTINUITY Link
                    db_manager.merge_relationship(
                        source_id=d_id,
                        target_id=a_id,
                        rel_type="SIM_CHURN_CONTINUITY",
                        properties={
                            "overlap_percentage": round(overlap_ratio * 100, 1),
                            "shared_targets": list(intersection),
                            "weight": 3.0,
                            "context": f"Bipartite Match Continuity ({pct_str} overlap)"
                        }
                    )
                    logger.info(f"SIM Churn Match Detected: {d_id} -> {a_id} ({pct_str} overlap)")

        return churn_matches

    def run_logistics_filter(self, nodes_dict: Dict[str, Dict[str, Any]]) -> int:
        """
        Phase 4: Logistics Filter (Women's Safety & Human Trafficking Anomaly):
        Conditional logic scanning financial transaction logs.
        Flag any node (alert: true) that executes repetitive transit ticket purchases
        alongside high-frequency, short-duration hotel bookings.
        """
        flagged_count = 0
        entity_transit: Dict[str, List[Dict[str, Any]]] = {}
        entity_hotels: Dict[str, List[Dict[str, Any]]] = {}

        # Scan financial logs
        transit_keywords = {"IRCTC", "RAIL", "BUS", "REDBUS", "MAKEMYTRIP", "AIR", "FLIGHT", "UBER", "TRANSIT_TICKET", "CAB"}
        hotel_keywords = {"OYO", "HOTEL", "TREEBO", "GINGER", "LODGE", "ROOMS", "HOTEL_BOOKING", "STAY"}

        for tx in self.financial_logs_registry:
            ent = tx["entity"]
            cat = tx["category"]
            merch = tx["merchant"].upper()
            
            is_transit = cat in ["TRANSIT_TICKET", "CAB_BOOKING", "AIR_TICKET"] or any(k in merch for k in transit_keywords)
            is_hotel = cat in ["HOTEL_BOOKING", "LODGING"] or any(k in merch for k in hotel_keywords)

            if is_transit:
                entity_transit.setdefault(ent, []).append(tx)
            if is_hotel:
                entity_hotels.setdefault(ent, []).append(tx)

        # Evaluate co-occurrence of repetitive transit + frequent hotel bookings
        all_entities = set(entity_transit.keys()).union(entity_hotels.keys())
        for ent in all_entities:
            t_count = len(entity_transit.get(ent, []))
            h_count = len(entity_hotels.get(ent, []))

            # Trigger condition: repetitive transit (>=2) and frequent hotel stays (>=2)
            if t_count >= 2 and h_count >= 2:
                flagged_count += 1
                reason = f"Logistics Alert (Women's Safety): Repetitive transit tickets ({t_count}x) paired with high-frequency short-duration hotel bookings ({h_count}x)"
                
                # Match to node in nodes_dict
                matched_node = None
                for nid, n in nodes_dict.items():
                    if nid == ent or n.get("label") == ent or ent in nid:
                        matched_node = n
                        break

                if matched_node:
                    matched_node["alert"] = True
                    matched_node.setdefault("alert_reasons", [])
                    if reason not in matched_node["alert_reasons"]:
                        matched_node["alert_reasons"].append(reason)
                    matched_node["details"]["alert"] = True
                    matched_node["details"]["alert_reasons"] = matched_node["alert_reasons"]
                    matched_node["details"]["transit_purchases_count"] = t_count
                    matched_node["details"]["hotel_bookings_count"] = h_count
                    db_manager.merge_node(matched_node["id"], matched_node["label"], matched_node["type"], matched_node["details"])
                    logger.warning(f"Flagged entity '{ent}' under Logistics Safety Filter ({t_count} transit, {h_count} hotel)")

        return flagged_count

    def compute_graph_metrics(self) -> Dict[str, Any]:
        """
        Full Graph ML & Algorithmic Engine:
        1. Evaluates BTS Co-Location time-window pings (<=10m).
        2. Builds in-memory NetworkX DiGraph.
        3. Executes nx.betweenness_centrality() -> node.centrality_score.
        4. Executes SIM Churn Bipartite Matching (>=85%).
        5. Executes Logistics Filter (Transit + Short Hotel Bookings).
        6. Computes PageRank and composite Risk Scores.
        """
        # 1. Evaluate BTS Co-Locations
        bts_count = self.run_bts_colocation_engine()

        nodes, links = db_manager.get_raw_graph()
        if not nodes:
            return {"status": "empty"}

        nodes_dict = {n["id"]: n for n in nodes}

        # 2. Build NetworkX DiGraph
        G = nx.DiGraph()
        for n in nodes:
            props = dict(n.get("details", {}))
            props["type"] = n.get("type", props.get("type", "Unknown"))
            G.add_node(n["id"], **props)

        for l in links:
            src = l["source"]["id"] if isinstance(l["source"], dict) else str(l["source"])
            tgt = l["target"]["id"] if isinstance(l["target"], dict) else str(l["target"])
            weight = float(l.get("weight", 1.0))
            if l.get("amount"):
                weight += min(float(l["amount"]) / 100000.0, 10.0)
            edge_props = dict(l.get("details", {}))
            edge_props["weight"] = weight
            edge_props["type"] = l.get("type", edge_props.get("type", "LINK"))
            G.add_edge(src, tgt, **edge_props)

        # 3. Phase 2: nx.betweenness_centrality() -> centrality_score
        try:
            betweenness = nx.betweenness_centrality(G, weight="weight")
        except Exception:
            betweenness = {n["id"]: 0.0 for n in nodes}

        # 4. PageRank & Degrees
        try:
            pagerank_scores = nx.pagerank(G, alpha=0.85, weight="weight", max_iter=200)
        except Exception:
            pagerank_scores = {n["id"]: 0.05 for n in nodes}

        in_deg = dict(G.in_degree())
        out_deg = dict(G.out_degree())

        # Community Detection
        undirected_G = G.to_undirected()
        communities = list(nx.connected_components(undirected_G))
        node_community_map = {}
        for c_idx, comp in enumerate(communities):
            for n_id in comp:
                node_community_map[n_id] = c_idx + 1

        # 5. Phase 4: SIM Churn & Logistics Threat Detection
        sim_churn_count = self.run_sim_churn_detection(G, nodes_dict)
        logistics_count = self.run_logistics_filter(nodes_dict)

        # 6. Composite Risk Score & Centrality Assignment
        max_pr = max(pagerank_scores.values()) if pagerank_scores.values() else 1.0
        max_pr = max(max_pr, 0.0001)
        max_bet = max(betweenness.values()) if betweenness.values() else 1.0
        max_bet = max(max_bet, 0.0001)

        for n in nodes:
            n_id = n["id"]
            node_type = n.get("type", "")
            pr = pagerank_scores.get(n_id, 0.0)
            deg = in_deg.get(n_id, 0) + out_deg.get(n_id, 0)
            bet = betweenness.get(n_id, 0.0)
            comm = node_community_map.get(n_id, 0)

            # Normalization
            norm_pr = pr / max_pr
            norm_bet = bet / max_bet
            norm_deg = min(deg / 6.0, 1.0)

            # Base risk scoring
            if node_type == "Suspect":
                base_risk = 0.50
                risk_score = (base_risk * 0.20) + (norm_pr * 0.30) + (norm_bet * 0.30) + (norm_deg * 0.20)
                if n.get("alert"):
                    risk_score += 0.20
            elif node_type == "BankAccount":
                base_risk = 0.45
                risk_score = (base_risk * 0.25) + (norm_pr * 0.35) + (norm_bet * 0.25) + (norm_deg * 0.15)
                if n.get("alert"):
                    risk_score += 0.20
            elif node_type == "Phone":
                base_risk = 0.30
                risk_score = (base_risk * 0.30) + (norm_pr * 0.35) + (norm_deg * 0.35)
                if n.get("alert"):
                    risk_score += 0.25
            elif node_type == "Vehicle":
                base_risk = 0.35
                risk_score = (base_risk * 0.40) + (norm_bet * 0.30) + (norm_deg * 0.30)
            elif node_type == "FIR":
                base_risk = 0.20
                risk_score = (base_risk * 0.40) + (norm_pr * 0.30) + (norm_deg * 0.30)
            else:
                base_risk = 0.15
                risk_score = (base_risk * 0.30) + (norm_pr * 0.35) + (norm_deg * 0.35)

            risk_score = round(min(max(risk_score, 0.05), 0.99), 3)
            centrality_score = round(bet, 4)

            n["centrality_score"] = centrality_score
            n["risk_score"] = risk_score
            n["pagerank"] = round(pr, 4)
            n["degree"] = deg
            n["community"] = comm

            n.setdefault("details", {})
            n["details"]["centrality_score"] = centrality_score
            n["details"]["risk_score"] = risk_score
            n["details"]["pagerank"] = round(pr, 4)
            n["details"]["betweenness"] = centrality_score
            n["details"]["degree"] = deg
            n["details"]["community"] = comm
            n["details"]["alert"] = n.get("alert", False)
            n["details"]["alert_reasons"] = n.get("alert_reasons", [])

            # Write back
            db_manager.merge_node(n_id, n.get("label", n_id), node_type, n["details"])

        logger.info(f"Graph ML update complete: {len(nodes)} nodes, {bts_count} BTS co-locations, {sim_churn_count} SIM churns, {logistics_count} logistics alerts.")
        return {
            "nodes_updated": len(nodes),
            "bts_colocations": bts_count,
            "sim_churn_matches": sim_churn_count,
            "logistics_alerts": logistics_count
        }

    def get_d3_graph(
        self,
        filter_type: Optional[str] = None,
        min_risk: float = 0.0,
        threats_only: bool = False
    ) -> GraphResponse:
        """
        Phase 5: Returns graph serialized for D3.js force simulation:
        { "nodes": [...], "links": [...], "summary": {...} }
        """
        nodes_raw, links_raw = db_manager.get_raw_graph()

        if nodes_raw and any(n.get("centrality_score") is None or n.get("risk_score", 0.0) == 0.0 for n in nodes_raw):
            self.compute_graph_metrics()
            nodes_raw, links_raw = db_manager.get_raw_graph()

        valid_node_ids = set()
        filtered_nodes: List[Node] = []

        for n in nodes_raw:
            n_type = n.get("type", "Unknown")
            n_risk = float(n.get("risk_score", 0.0))
            is_alert = bool(n.get("alert", False))

            if filter_type and filter_type != "ALL" and n_type.lower() != filter_type.lower():
                continue
            if n_risk < min_risk:
                continue
            if threats_only and not is_alert:
                continue

            valid_node_ids.add(n["id"])
            filtered_nodes.append(Node(
                id=n["id"],
                label=n.get("label", n["id"]),
                type=n_type,
                centrality_score=float(n.get("centrality_score", n.get("details", {}).get("centrality_score", 0.0))),
                risk_score=n_risk,
                pagerank=float(n.get("pagerank", 0.0)),
                degree=int(n.get("degree", 0)),
                community=int(n.get("community", 0)),
                alert=is_alert,
                alert_reasons=n.get("alert_reasons", []),
                sha256_hash=n.get("sha256_hash") or n.get("details", {}).get("sha256_hash"),
                details=n.get("details", {})
            ))

        filtered_links: List[Link] = []
        total_fraud_volume = 0.0
        bts_links = 0
        sim_churn_links = 0

        for l in links_raw:
            src = l["source"]
            tgt = l["target"]
            src_id = src["id"] if isinstance(src, dict) else str(src)
            tgt_id = tgt["id"] if isinstance(tgt, dict) else str(tgt)

            if src_id in valid_node_ids and tgt_id in valid_node_ids:
                l_type = l.get("type", "ASSOCIATED_WITH")
                if l_type == "CO_LOCATED":
                    bts_links += 1
                elif l_type == "SIM_CHURN_CONTINUITY":
                    sim_churn_links += 1

                amt = l.get("amount")
                if amt:
                    try:
                        total_fraud_volume += float(amt)
                    except ValueError:
                        pass

                filtered_links.append(Link(
                    id=l.get("id"),
                    source=src_id,
                    target=tgt_id,
                    type=l_type,
                    weight=float(l.get("weight", 1.0)),
                    amount=amt,
                    details=l.get("details", {})
                ))

        summary = GraphSummary(
            total_nodes=len(filtered_nodes),
            total_links=len(filtered_links),
            suspect_count=sum(1 for n in filtered_nodes if n.type == "Suspect"),
            bank_account_count=sum(1 for n in filtered_nodes if n.type == "BankAccount"),
            location_count=sum(1 for n in filtered_nodes if n.type == "Location"),
            fir_count=sum(1 for n in filtered_nodes if n.type == "FIR"),
            phone_count=sum(1 for n in filtered_nodes if n.type == "Phone"),
            vehicle_count=sum(1 for n in filtered_nodes if n.type == "Vehicle"),
            high_risk_count=sum(1 for n in filtered_nodes if n.risk_score >= 0.70),
            threat_alert_count=sum(1 for n in filtered_nodes if n.alert),
            bts_colocation_count=bts_links,
            sim_churn_count=sim_churn_links,
            total_fraud_volume=total_fraud_volume,
            neo4j_connected=db_manager.is_connected
        )

        return GraphResponse(
            nodes=filtered_nodes,
            links=filtered_links,
            summary=summary
        )

    def get_node_details(self, node_id: str) -> Optional[NodeDetailResponse]:
        """Provides rich forensic breakdown for side-panel inspection on node click."""
        nodes_raw, links_raw = db_manager.get_raw_graph()
        target_node = None
        for n in nodes_raw:
            if n["id"] == node_id:
                target_node = n
                break
        if not target_node:
            return None

        neighbors = []
        related_firs = []
        for l in links_raw:
            src = l["source"]["id"] if isinstance(l["source"], dict) else str(l["source"])
            tgt = l["target"]["id"] if isinstance(l["target"], dict) else str(l["target"])

            if src == node_id or tgt == node_id:
                other_id = tgt if src == node_id else src
                direction = "OUTGOING" if src == node_id else "INCOMING"
                other_node = next((item for item in nodes_raw if item["id"] == other_id), None)
                if other_node:
                    neighbors.append({
                        "node_id": other_id,
                        "label": other_node.get("label", other_id),
                        "type": other_node.get("type", "Unknown"),
                        "relationship": l.get("type"),
                        "direction": direction,
                        "amount": l.get("amount"),
                        "risk_score": other_node.get("risk_score", 0.0),
                        "alert": other_node.get("alert", False)
                    })
                    if other_node.get("type") == "FIR":
                        related_firs.append(other_node.get("details", {}))

        if target_node.get("type") == "FIR":
            related_firs.append(target_node.get("details", {}))

        return NodeDetailResponse(
            id=target_node["id"],
            label=target_node.get("label", target_node["id"]),
            type=target_node.get("type", "Unknown"),
            centrality_score=float(target_node.get("centrality_score", 0.0)),
            risk_score=float(target_node.get("risk_score", 0.0)),
            pagerank=float(target_node.get("pagerank", 0.0)),
            degree=int(target_node.get("degree", 0)),
            community=int(target_node.get("community", 0)),
            alert=bool(target_node.get("alert", False)),
            alert_reasons=target_node.get("alert_reasons", []),
            sha256_hash=target_node.get("sha256_hash") or target_node.get("details", {}).get("sha256_hash"),
            details=target_node.get("details", {}),
            neighbors=neighbors,
            related_evidence=related_firs
        )

graph_service = GraphService()
