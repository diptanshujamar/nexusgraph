import os
import sys
import unittest
from fastapi.testclient import TestClient

# Add backend to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from scripts.ingest_data import run_ingestion

class TestAPIEndpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        run_ingestion()

    def test_health_endpoint(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "online")
        self.assertIn("system", data)

    def test_network_endpoint_structure(self):
        """Test Phase 5: /api/network endpoint structure."""
        res = self.client.get("/api/network")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        
        self.assertIn("nodes", data)
        self.assertIn("links", data)
        self.assertIn("summary", data)
        self.assertGreater(len(data["nodes"]), 0)
        self.assertGreater(len(data["links"]), 0)
        
        # Verify node attributes
        sample_node = data["nodes"][0]
        self.assertIn("id", sample_node)
        self.assertIn("label", sample_node)
        self.assertIn("type", sample_node)
        self.assertIn("centrality_score", sample_node)
        self.assertIn("risk_score", sample_node)
        self.assertIn("alert", sample_node)

    def test_bsa_certificate_download_endpoint(self):
        """Test Phase 3: Section 63(4) BSA PDF download endpoint."""
        sha256 = "fd0da1119eb28c27f867209976f89afc7c4ed64982d9b6789c67540aae2c576b"
        res = self.client.get(f"/api/bsa-certificate/download?sha256_hash={sha256}&case_reference=CR-2026-DEL-101")
        
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "application/pdf")
        self.assertIn("BSA_Sec63_4_Certificate", res.headers["content-disposition"])
        self.assertTrue(res.content.startswith(b"%PDF-1.4"))
        self.assertIn(b"SECTION 63(4)", res.content)
        self.assertIn(b"PART A", res.content)
        self.assertIn(b"PART B", res.content)

    def test_analyze_fir_endpoint(self):
        """Test Phase 1 & 3: Real-time FIR analysis and SHA-256 calculation."""
        payload = {
            "fir_number": "FIR-2026-LIVE-999",
            "police_station": "Cyber Cell, Connaught Place",
            "incident_date": "2026-08-31",
            "state": "Delhi",
            "text": "Suspect Vikram Singhaniya driving vehicle DL-01-AB-1234 transferred Rs 10,00,000 to account 918234509122."
        }
        res = self.client.post("/api/analyze-fir", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        
        self.assertEqual(data["fir_number"], "FIR-2026-LIVE-999")
        self.assertEqual(len(data["sha256_hash"]), 64)
        self.assertIn("DL-01-AB-1234", data["extracted_vehicles"])
        self.assertIn("918234509122", data["extracted_bank_accounts"])

    def test_threat_intelligence_endpoint(self):
        """Test Phase 4: /api/threats endpoint."""
        res = self.client.get("/api/threats")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        
        self.assertIn("threat_count", data)
        self.assertIn("threat_nodes", data)
        self.assertIn("bts_colocations", data)
        self.assertIn("sim_churn_events", data)

    def test_heatmap_endpoint(self):
        """Test Geospatial Crime Heatmap endpoint."""
        res = self.client.get("/api/heatmap")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        
        self.assertIn("points", data)
        self.assertIn("towers", data)
        self.assertIn("corridors", data)
        self.assertIn("summary", data)
        self.assertGreater(len(data["points"]), 0)
        self.assertGreater(len(data["towers"]), 0)
        self.assertGreater(len(data["corridors"]), 0)
        self.assertIn("Delhi", [p["city"] for p in data["points"]])

    def test_demographics_endpoint(self):
        """Test Victim Demographics, Age Group & Gender Crime Analytics endpoint."""
        res = self.client.get("/api/analytics/demographics")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        
        self.assertIn("suspect_age_matrix", data)
        self.assertIn("gender_crime_matrix", data)
        self.assertIn("age_group_summary", data)
        self.assertIn("gender_summary", data)
        self.assertIn("kpis", data)
        self.assertGreater(len(data["suspect_age_matrix"]), 0)
        self.assertGreater(len(data["gender_crime_matrix"]), 0)
        
        # Verify Rahul Mondal youth targeting
        rahul = next((s for s in data["suspect_age_matrix"] if "Rahul" in s["suspect_name"]), None)
        self.assertIsNotNone(rahul)
        self.assertGreater(rahul["age_18_25"], 20)

    def test_apb_broadcast_endpoint(self):
        """Test Inter-Agency Police Station APB Broadcast endpoint."""
        payload = {
            "suspect_id": "SUSPECT:vikram_singhania",
            "priority_level": "FLASH_RED_ALERT",
            "selected_stations": ["delhi_special_cell", "mumbai_bkc"],
            "include_vehicles": True,
            "include_bank_accounts": False,
            "originating_officer": "Insp. R. K. Verma",
            "case_reference": "CR-2026-DEL-101"
        }
        res = self.client.post("/api/broadcast/apb", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        
        self.assertIn("broadcast_id", data)
        self.assertIn("cctns_reference", data)
        self.assertEqual(data["suspect_name"], "Vikram Singhania")
        self.assertEqual(len(data["dispatched_stations"]), 2)
        self.assertEqual(len(data["sha256_hash"]), 64)
        self.assertEqual(data["bank_accounts"], ["Excluded from Dispatch"])
        
        # Test history endpoint
        hist_res = self.client.get("/api/broadcast/history")
        self.assertEqual(hist_res.status_code, 200)
        hist_data = hist_res.json()
        self.assertGreaterEqual(len(hist_data["broadcasts"]), 1)

if __name__ == "__main__":
    unittest.main()
