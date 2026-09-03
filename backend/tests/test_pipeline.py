import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.graph_service import graph_service
from app.nlp_pipeline import nlp_pipeline
from app.database import db_manager
from scripts.ingest_data import run_ingestion

def test_full_pipeline():
    print("Testing Ingestion...")
    run_ingestion()
    
    print("\nTesting D3 Graph API serialization...")
    d3_graph = graph_service.get_d3_graph()
    print(f"Total Nodes: {len(d3_graph.nodes)}")
    print(f"Total Links: {len(d3_graph.links)}")
    
    # Check top nodes by risk
    sorted_nodes = sorted(d3_graph.nodes, key=lambda x: x.risk_score, reverse=True)
    print("\nTop 5 Nodes by Risk Score:")
    for n in sorted_nodes[:5]:
        print(f"  [{n.type}] {n.label} (ID: {n.id}) - Risk: {n.risk_score} | PageRank: {n.pagerank} | Degree: {n.degree}")

    # Check node details
    test_node_id = sorted_nodes[0].id
    print(f"\nTesting Node Detail Fetch for {test_node_id}...")
    details = graph_service.get_node_details(test_node_id)
    assert details is not None
    print(f"  Node: {details.label}")
    print(f"  Neighbors count: {len(details.neighbors)}")
    print(f"  Related evidence count: {len(details.related_evidence)}")

    # Test NLP Extraction on sample FIR
    print("\nTesting NLP Extraction on Sample FIR text...")
    sample_text = (
        "FIR against Rohit Sharma (Account: 998877665544) who coordinated with Suresh Reddy "
        "to launder Rs 15,00,000 in Connaught Place, New Delhi. Phone: 9811002233."
    )
    res = nlp_pipeline.process_fir_text("FIR-TEST-001", sample_text, {"police_station": "Crime Branch", "state": "Delhi"})
    print(f"  Extracted suspects: {res['suspects']}")
    print(f"  Extracted accounts: {res['bank_accounts']}")
    print(f"  Extracted locations: {res['locations']}")
    print(f"  Extracted amounts: {res['amounts']}")
    print(f"  Extracted phones: {res['phone_numbers']}")
    print(f"  Generated nodes: {len(res['nodes'])}, links: {len(res['links'])}")

    assert len(res["suspects"]) >= 1
    assert "998877665544" in res["bank_accounts"]
    print("\nAll pipeline verification tests passed successfully!")

if __name__ == "__main__":
    test_full_pipeline()
