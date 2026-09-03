import os
import sys
import unittest
import networkx as nx

# Add backend to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.nlp_pipeline import nlp_pipeline
from app.graph_service import graph_service
from app.bsa_crypto import bsa_crypto
from app.database import db_manager

class TestBSAPipeline(unittest.TestCase):

    def setUp(self):
        db_manager.clear_all()
        graph_service.tower_pings_registry.clear()
        graph_service.financial_logs_registry.clear()
        nlp_pipeline.suspect_canonical_profiles.clear()

    def test_levenshtein_distance_and_fuzzy_resolution(self):
        """Test Phase 1: Levenshtein distance <= 2 suspect name deduplication."""
        # 1. Direct Levenshtein computation
        dist1 = nlp_pipeline.compute_levenshtein("Rahul", "Raahul")
        self.assertEqual(dist1, 1)
        self.assertLessEqual(dist1, 2)

        dist2 = nlp_pipeline.compute_levenshtein("Vikram Singhania", "Vikram Singhaniya")
        self.assertEqual(dist2, 1)
        self.assertLessEqual(dist2, 2)

        # 2. Suspect profile unification
        can_id1, can_name1, merged1 = nlp_pipeline.resolve_suspect_profile("Rahul Mondal")
        self.assertFalse(merged1)
        self.assertEqual(can_id1, "SUSPECT:rahul_mondal")

        can_id2, can_name2, merged2 = nlp_pipeline.resolve_suspect_profile("Raahul Mondal")
        self.assertTrue(merged2)
        self.assertEqual(can_id2, can_id1)
        self.assertEqual(can_name2, "Rahul Mondal")

    def test_spacy_target_extraction(self):
        """Test Phase 1: Extraction of PERSON, LOC, BANK_ACC, VEHICLE_REG."""
        sample_text = (
            "Suspect Amit Verma driving car DL-01-AB-1234 transferred Rs 15,00,000 "
            "into account 918234509122 at Connaught Place, New Delhi using phone 9810011223."
        )
        res = nlp_pipeline.process_fir_text("FIR-TEST-001", sample_text)
        
        self.assertIn("Amit Verma", res["suspects"])
        self.assertIn("DL-01-AB-1234", res["vehicles"])
        self.assertIn("918234509122", res["bank_accounts"])
        self.assertIn("9810011223", res["phone_numbers"])
        self.assertTrue(any("Delhi" in loc for loc in res["locations"]))

    def test_sha256_and_bsa_section63_pdf_certificate(self):
        """Test Phase 3: Cryptographic SHA-256 and Section 63(4) BSA 2023 Two-Part PDF Certificate."""
        raw_evidence = b"CRIMINAL FORENSIC RECORD BITSTREAM 2026"
        sha256_hash = bsa_crypto.calculate_sha256_data(raw_evidence, label="Test Evidence Log")
        
        self.assertEqual(len(sha256_hash), 64)
        
        # Generate Section 63(4) BSA PDF Certificate
        pdf_bytes = bsa_crypto.generate_bsa_pdf_certificate(
            sha256_hash=sha256_hash,
            case_reference="CR-2026-TEST-01",
            operator_name="Insp. Test Operator",
            expert_name="Dr. Test Expert"
        )
        
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertGreater(len(pdf_bytes), 1000)
        # Verify SHA-256 string and Part A/B are in the PDF byte stream
        self.assertIn(sha256_hash.encode("latin-1"), pdf_bytes)
        self.assertIn(b"SECTION 63(4)", pdf_bytes)
        self.assertIn(b"PART A", pdf_bytes)
        self.assertIn(b"PART B", pdf_bytes)

    def test_sim_churn_bipartite_matching(self):
        """Test Phase 4: SIM Churn detection via bipartite target overlap >= 85%."""
        # Setup deactivated phone and active replacement phone calling same targets
        d_phone = "PHONE:9800000001"
        a_phone = "PHONE:9800000002"
        
        db_manager.merge_node(d_phone, "Old Phone", "Phone", {"phone_number": "9800000001", "status": "Deactivated"})
        db_manager.merge_node(a_phone, "New Phone", "Phone", {"phone_number": "9800000002", "status": "Active"})
        
        targets = [f"PHONE:980000000{i}" for i in range(3, 8)]
        for t in targets:
            db_manager.merge_node(t, f"Target {t}", "Phone", {"status": "Active"})
            db_manager.merge_relationship(d_phone, t, "COMMUNICATED_WITH")
            db_manager.merge_relationship(a_phone, t, "COMMUNICATED_WITH")
            
        metrics = graph_service.compute_graph_metrics()
        self.assertGreaterEqual(metrics["sim_churn_matches"], 1)
        
        # Check that nodes received threat alerts
        d_details = graph_service.get_node_details(d_phone)
        self.assertTrue(d_details.alert)
        self.assertTrue(any("SIM Churn" in r for r in d_details.alert_reasons))

    def test_logistics_filter_women_safety(self):
        """Test Phase 4: Logistics filter flagging transit + short-duration hotel bookings."""
        account_id = "440192837461"
        db_manager.merge_node(f"ACCOUNT:{account_id}", f"A/C {account_id}", "BankAccount", {"account_number": account_id})
        
        # Register repetitive transit and frequent hotel stays
        graph_service.register_financial_tx(account_id, "TRANSIT_TICKET", "IRCTC Delhi-Mumbai", 3500.0, "2026-08-15 10:00:00")
        graph_service.register_financial_tx(account_id, "HOTEL_BOOKING", "OYO Flagship Delhi", 2500.0, "2026-08-15 14:00:00")
        graph_service.register_financial_tx(account_id, "TRANSIT_TICKET", "RedBus Sleeper", 2000.0, "2026-08-17 19:00:00")
        graph_service.register_financial_tx(account_id, "HOTEL_BOOKING", "Treebo Trend Jaipur", 3100.0, "2026-08-18 01:00:00")
        
        metrics = graph_service.compute_graph_metrics()
        self.assertGreaterEqual(metrics["logistics_alerts"], 1)
        
        acc_details = graph_service.get_node_details(f"ACCOUNT:{account_id}")
        self.assertTrue(acc_details.alert)
        self.assertTrue(any("Logistics Alert" in r for r in acc_details.alert_reasons))

    def test_bts_colocation_engine(self):
        """Test Phase 4: BTS cell tower co-location within 10-minute threshold."""
        graph_service.register_tower_ping("9810011223", "TOWER-TEST-500", "2026-08-20 14:00:00")
        graph_service.register_tower_ping("9820099881", "TOWER-TEST-500", "2026-08-20 14:06:00") # 6 min delta <= 10 min
        
        db_manager.merge_node("PHONE:9810011223", "Phone 1", "Phone", {"phone_number": "9810011223"})
        db_manager.merge_node("PHONE:9820099881", "Phone 2", "Phone", {"phone_number": "9820099881"})
        
        metrics = graph_service.compute_graph_metrics()
        self.assertGreaterEqual(metrics["bts_colocations"], 1)
        
        d3_graph = graph_service.get_d3_graph()
        colocated_links = [l for l in d3_graph.links if l.type == "CO_LOCATED"]
        self.assertGreaterEqual(len(colocated_links), 1)

    def test_betweenness_centrality_assignment(self):
        """Test Phase 2: nx.betweenness_centrality assigning float value to centrality_score."""
        # Create a bridge topology: A <-> Bridge <-> B
        db_manager.merge_node("NODE:A", "Node A", "Suspect", {})
        db_manager.merge_node("NODE:BRIDGE", "Bridge Node", "Suspect", {})
        db_manager.merge_node("NODE:B", "Node B", "Suspect", {})
        
        db_manager.merge_relationship("NODE:A", "NODE:BRIDGE", "ASSOCIATED_WITH")
        db_manager.merge_relationship("NODE:BRIDGE", "NODE:B", "ASSOCIATED_WITH")
        
        graph_service.compute_graph_metrics()
        
        d3_graph = graph_service.get_d3_graph()
        bridge_node = next(n for n in d3_graph.nodes if n.id == "NODE:BRIDGE")
        
        self.assertIsNotNone(bridge_node.centrality_score)
        self.assertIsInstance(bridge_node.centrality_score, float)
        self.assertGreater(bridge_node.centrality_score, 0.0)

if __name__ == "__main__":
    unittest.main()
