import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app
from scripts.ingest_data import run_ingestion

def test_api_endpoints():
    with TestClient(app) as client:
        # Ensure data is populated
        run_ingestion()

        print("Testing /api/health...")
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "online"
        print("  ✓ /api/health is online")

        print("\nTesting /api/graph...")
        res = client.get("/api/graph")
        assert res.status_code == 200
        data = res.json()
        assert "nodes" in data and "links" in data and "summary" in data
        assert len(data["nodes"]) > 0
        assert len(data["links"]) > 0
        print(f"  ✓ /api/graph returned {len(data['nodes'])} nodes and {len(data['links'])} links")

        print("\nTesting /api/graph with filters (Suspect only)...")
        res = client.get("/api/graph?filter_type=Suspect")
        assert res.status_code == 200
        filtered_data = res.json()
        assert len(filtered_data["nodes"]) > 0
        assert all(n["type"] == "Suspect" for n in filtered_data["nodes"])
        print(f"  ✓ Filtered graph contains {len(filtered_data['nodes'])} suspects")

        print("\nTesting /api/stats...")
        res = client.get("/api/stats")
        assert res.status_code == 200
        stats = res.json()
        assert stats["total_nodes"] > 0
        print(f"  ✓ Total nodes: {stats['total_nodes']}, High-Risk: {stats['high_risk_count']}")

        print("\nTesting /api/node/{node_id} detail inspector...")
        test_node_id = data["nodes"][0]["id"]
        res = client.get(f"/api/node/{test_node_id}")
        assert res.status_code == 200
        node_detail = res.json()
        assert node_detail["id"] == test_node_id
        assert "neighbors" in node_detail
        assert "details" in node_detail
        print(f"  ✓ Fetched details for {node_detail['label']} with {len(node_detail['neighbors'])} connections")

        print("\nTesting /api/analyze-fir (On-the-fly NLP Ingestion)...")
        payload = {
            "fir_number": "FIR-2026-TEST-LIVE",
            "police_station": "Special Cyber Unit, Cyberabad",
            "incident_date": "2026-08-31",
            "state": "Telangana",
            "text": (
                "Cyber syndicate led by accused Rohan Bansal and Devendra Joshi defrauded victim of Rs 40,00,000. "
                "Funds deposited into mule account 990011223344 (Axis Bank, Hyderabad) and transferred Rs 20,00,000 "
                "to accomplice Vikram Singhania in Delhi. Phone number: 9849012345."
            )
        }
        res = client.post("/api/analyze-fir", json=payload)
        assert res.status_code == 200
        fir_res = res.json()
        assert "990011223344" in fir_res["extracted_bank_accounts"]
        print(f"  ✓ Successfully analyzed FIR: {fir_res['fir_number']}")
        print(f"    Suspects: {fir_res['extracted_suspects']}")
        print(f"    Accounts: {fir_res['extracted_bank_accounts']}")
        print(f"    Locations: {fir_res['extracted_locations']}")
        print(f"    Nodes added: {fir_res['nodes_added']}, Links added: {fir_res['links_added']}")

        print("\nTesting GET / (Dashboard HTML frontend)...")
        res = client.get("/")
        assert res.status_code == 200
        assert "NEXUS" in res.text
        print("  ✓ Root dashboard HTML served successfully.")

        print("\n=======================================================")
        print("ALL API ENDPOINT INTEGRATION TESTS PASSED (100% OK)!")
        print("=======================================================")

if __name__ == "__main__":
    test_api_endpoints()
