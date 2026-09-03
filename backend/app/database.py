import os
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from dotenv import load_dotenv
import networkx as nx

load_dotenv()

logger = logging.getLogger("crime_intelligence.db")
logging.basicConfig(level=logging.INFO)

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

class DatabaseManager:
    """
    Manages Neo4j database connections and in-memory fallback graph (NetworkX).
    Supports comprehensive forensic metadata: centrality_score, alert, alert_reasons, and sha256_hash.
    """
    def __init__(self):
        self._driver = None
        self._fallback_graph = nx.MultiDiGraph()
        self._fallback_nodes_meta: Dict[str, Dict[str, Any]] = {}
        self._fallback_links_meta: List[Dict[str, Any]] = []
        self._connected = False
        self._last_connect_attempt = 0.0
        self.try_connect(force=True)

    def try_connect(self, force: bool = False) -> bool:
        """Attempts to establish connection with Neo4j with rate-limiting."""
        now = time.time()
        if not force and (now - self._last_connect_attempt) < 15.0:
            return self._connected
        self._last_connect_attempt = now

        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                NEO4J_URI,
                auth=(NEO4J_USER, NEO4J_PASSWORD),
                max_connection_lifetime=200
            )
            with self._driver.session(database=NEO4J_DATABASE) as session:
                result = session.run("RETURN 1 AS ping")
                record = result.single()
                if record and record["ping"] == 1:
                    self._connected = True
                    logger.info(f"Successfully connected to Neo4j at {NEO4J_URI}")
                    return True
        except Exception as e:
            if self._connected or force:
                logger.warning(f"Neo4j not reachable at {NEO4J_URI} ({e}). Operating in in-memory graph mode.")
            self._connected = False
        return False

    @property
    def is_connected(self) -> bool:
        return self._connected or self.try_connect()

    def close(self):
        if self._driver:
            self._driver.close()

    def init_schema(self) -> Dict[str, Any]:
        """Creates unique constraints and indexes in Neo4j."""
        constraints = [
            "CREATE CONSTRAINT suspect_id_unique IF NOT EXISTS FOR (s:Suspect) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT bank_account_unique IF NOT EXISTS FOR (b:BankAccount) REQUIRE b.account_number IS UNIQUE",
            "CREATE CONSTRAINT location_name_unique IF NOT EXISTS FOR (l:Location) REQUIRE l.name IS UNIQUE",
            "CREATE CONSTRAINT fir_number_unique IF NOT EXISTS FOR (f:FIR) REQUIRE f.fir_number IS UNIQUE",
            "CREATE CONSTRAINT phone_number_unique IF NOT EXISTS FOR (p:Phone) REQUIRE p.phone_number IS UNIQUE",
            "CREATE CONSTRAINT vehicle_id_unique IF NOT EXISTS FOR (v:Vehicle) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT org_name_unique IF NOT EXISTS FOR (o:Organization) REQUIRE o.name IS UNIQUE",
            "CREATE INDEX suspect_risk_idx IF NOT EXISTS FOR (s:Suspect) ON (s.risk_score)",
            "CREATE INDEX bank_risk_idx IF NOT EXISTS FOR (b:BankAccount) ON (b.risk_score)"
        ]
        
        executed = []
        if self.is_connected:
            with self._driver.session(database=NEO4J_DATABASE) as session:
                for c in constraints:
                    try:
                        session.run(c)
                        executed.append(c)
                    except Exception as e:
                        logger.error(f"Error applying constraint '{c}': {e}")
            logger.info(f"Applied {len(executed)} constraints/indexes to Neo4j.")
        return {"neo4j_connected": self._connected, "applied": executed}

    def merge_node(self, node_id: str, label: str, node_type: str, properties: Dict[str, Any]):
        """Merges a node into Neo4j and in-memory graph with full threat & forensic attributes."""
        clean_props = {k: v for k, v in properties.items() if v is not None}
        clean_props["id"] = node_id
        clean_props["label"] = label
        clean_props["type"] = node_type

        # Extract first-class fields
        centrality_score = float(clean_props.get("centrality_score", 0.0))
        risk_score = float(clean_props.get("risk_score", 0.0))
        pagerank = float(clean_props.get("pagerank", 0.0))
        degree = int(clean_props.get("degree", 0))
        community = int(clean_props.get("community", 0))
        alert = bool(clean_props.get("alert", False))
        alert_reasons = list(clean_props.get("alert_reasons", []))
        sha256_hash = clean_props.get("sha256_hash")

        # 1. In-memory fallback
        self._fallback_graph.add_node(node_id, **clean_props)
        self._fallback_nodes_meta[node_id] = {
            "id": node_id,
            "label": label,
            "type": node_type,
            "centrality_score": centrality_score,
            "risk_score": risk_score,
            "pagerank": pagerank,
            "degree": degree,
            "community": community,
            "alert": alert,
            "alert_reasons": alert_reasons,
            "sha256_hash": sha256_hash,
            "details": clean_props
        }

        # 2. Neo4j write if online
        if self.is_connected:
            cypher = f"""
            MERGE (n:{node_type} {{id: $id}})
            SET n += $props, n.label = $label, n.centrality_score = $centrality_score,
                n.risk_score = $risk_score, n.alert = $alert, n.sha256_hash = $sha256_hash
            RETURN n
            """
            try:
                with self._driver.session(database=NEO4J_DATABASE) as session:
                    session.run(cypher, {
                        "id": node_id,
                        "label": label,
                        "centrality_score": centrality_score,
                        "risk_score": risk_score,
                        "alert": alert,
                        "sha256_hash": sha256_hash,
                        "props": clean_props
                    })
            except Exception as e:
                logger.error(f"Error merging node {node_id} in Neo4j: {e}")

    def merge_relationship(self, source_id: str, target_id: str, rel_type: str, properties: Dict[str, Any] = None):
        """Merges a directed relationship between two nodes."""
        properties = properties or {}
        clean_props = {k: v for k, v in properties.items() if v is not None}
        rel_type_safe = rel_type.upper().replace(" ", "_")

        # 1. Update in-memory fallback
        self._fallback_graph.add_edge(source_id, target_id, key=rel_type_safe, type=rel_type_safe, **clean_props)
        self._fallback_links_meta.append({
            "source": source_id,
            "target": target_id,
            "type": rel_type_safe,
            "weight": float(clean_props.get("weight", 1.0)),
            "amount": clean_props.get("amount"),
            "details": clean_props
        })

        # 2. Update Neo4j if online
        if self.is_connected:
            cypher = f"""
            MATCH (a {{id: $source_id}})
            MATCH (b {{id: $target_id}})
            MERGE (a)-[r:{rel_type_safe}]->(b)
            SET r += $props
            RETURN r
            """
            try:
                with self._driver.session(database=NEO4J_DATABASE) as session:
                    session.run(cypher, {
                        "source_id": source_id,
                        "target_id": target_id,
                        "props": clean_props
                    })
            except Exception as e:
                logger.error(f"Error merging rel ({source_id})-[:{rel_type_safe}]->({target_id}) in Neo4j: {e}")

    def get_raw_graph(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Fetches all nodes and relationships."""
        if self.is_connected:
            try:
                cypher = """
                MATCH (n)
                OPTIONAL MATCH (n)-[r]->(m)
                RETURN n, r, m
                """
                nodes_dict = {}
                links_list = []
                with self._driver.session(database=NEO4J_DATABASE) as session:
                    results = session.run(cypher)
                    for record in results:
                        n = record["n"]
                        if n:
                            n_props = dict(n.items())
                            n_id = n_props.get("id", str(n.id))
                            n_labels = list(n.labels)
                            n_type = n_labels[0] if n_labels else n_props.get("type", "Unknown")
                            if n_id not in nodes_dict:
                                nodes_dict[n_id] = {
                                    "id": n_id,
                                    "label": n_props.get("label", n_props.get("name", n_id)),
                                    "type": n_type,
                                    "centrality_score": float(n_props.get("centrality_score", 0.0)),
                                    "risk_score": float(n_props.get("risk_score", 0.0)),
                                    "pagerank": float(n_props.get("pagerank", 0.0)),
                                    "degree": int(n_props.get("degree", 0)),
                                    "community": int(n_props.get("community", 0)),
                                    "alert": bool(n_props.get("alert", False)),
                                    "alert_reasons": list(n_props.get("alert_reasons", [])),
                                    "sha256_hash": n_props.get("sha256_hash"),
                                    "details": n_props
                                }
                        
                        r = record["r"]
                        m = record["m"]
                        if r and m:
                            r_props = dict(r.items())
                            m_props = dict(m.items())
                            m_id = m_props.get("id", str(m.id))
                            links_list.append({
                                "id": str(r.id),
                                "source": n_props.get("id", str(n.id)),
                                "target": m_id,
                                "type": r.type,
                                "weight": float(r_props.get("weight", 1.0)),
                                "amount": r_props.get("amount"),
                                "details": r_props
                            })
                if nodes_dict:
                    return list(nodes_dict.values()), links_list
            except Exception as e:
                logger.error(f"Failed to query Neo4j graph ({e}). Using fallback.", exc_info=True)

        # Fallback in-memory
        nodes = list(self._fallback_nodes_meta.values())
        seen_links = set()
        dedup_links = []
        for l in self._fallback_links_meta:
            src = l["source"]
            tgt = l["target"]
            typ = l["type"]
            key = (src, tgt, typ)
            if key not in seen_links:
                seen_links.add(key)
                dedup_links.append(l)
        return nodes, dedup_links

    def clear_all(self):
        """Clears all graph data."""
        self._fallback_graph.clear()
        self._fallback_nodes_meta.clear()
        self._fallback_links_meta.clear()
        if self.is_connected:
            try:
                with self._driver.session(database=NEO4J_DATABASE) as session:
                    session.run("MATCH (n) DETACH DELETE n")
            except Exception as e:
                logger.error(f"Error clearing Neo4j: {e}")

db_manager = DatabaseManager()
