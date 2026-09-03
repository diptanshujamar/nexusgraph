import os
import sys
import csv
import pandas as pd

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import db_manager
from app.nlp_pipeline import nlp_pipeline
from app.graph_service import graph_service
from app.bsa_crypto import bsa_crypto
from app.java_bridge import java_bridge
from app.mock_data_generator import generate_mock_files

def run_ingestion():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.abspath(os.path.join(current_dir, "..", "data"))
    
    firs_csv = os.path.join(data_dir, "mock_firs.csv")
    cdr_csv = os.path.join(data_dir, "mock_cdr.csv")
    fin_csv = os.path.join(data_dir, "mock_financial_logs.csv")

    # Generate mock CSVs if they don't exist
    if not os.path.exists(firs_csv) or not os.path.exists(cdr_csv) or not os.path.exists(fin_csv):
        print("Mock CSV files not found. Generating mock datasets...")
        generate_mock_files(data_dir)

    print("=" * 70)
    print("STARTING FORENSIC DATA INGESTION & THREAT DETECTION PIPELINE")
    print("=" * 70)

    # 1. Initialize schema
    db_manager.init_schema()

    # 2. Ingest Unstructured FIRs with Immediate SHA-256 Calculation & spaCy Targets
    print(f"\n[1/4] Ingesting FIRs from {firs_csv}...")
    fir_sha256 = bsa_crypto.calculate_sha256_file(firs_csv)
    print(f"  🔒 SHA-256 Hash calculated immediately: {fir_sha256}")

    fir_count = 0
    with open(firs_csv, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            fir_no = row["fir_number"]
            raw_text = row["raw_text"]
            extra_meta = {
                "police_station": row.get("police_station", "Cyber Crime PS"),
                "incident_date": row.get("incident_date", "2026-08-30"),
                "state": row.get("state", "Delhi"),
                "ipc_sections": row.get("ipc_sections", "")
            }

            # Ingest & Resolve Entities via spaCy + Levenshtein Fuzzy Deduplication
            extracted = nlp_pipeline.process_fir_text(fir_no, raw_text, extra_meta, sha256_hash=fir_sha256)

            # Ingest Nodes
            for node in extracted["nodes"]:
                db_manager.merge_node(
                    node_id=node["id"],
                    label=node["label"],
                    node_type=node["type"],
                    properties=node.get("details", {})
                )

            # Ingest Relationships
            for link in extracted["links"]:
                db_manager.merge_relationship(
                    source_id=link["source"],
                    target_id=link["target"],
                    rel_type=link["type"],
                    properties=link.get("details", {})
                )

            fir_count += 1
            print(f"  ✓ Processed {fir_no}: Suspects: {extracted['suspects']}, Vehicles: {extracted['vehicles']}, Accounts: {extracted['bank_accounts']}")

    # 3. Ingest Call Detail Records (CDRs) for BTS Co-Location & SIM Churn Tracking
    print(f"\n[2/4] Ingesting CDR logs from {cdr_csv} via Java/Pandas Bridge...")
    cdr_sha256 = bsa_crypto.calculate_sha256_file(cdr_csv)
    print(f"  🔒 SHA-256 Hash calculated immediately: {cdr_sha256}")

    cdr_records = java_bridge.parse_cdr_file(cdr_csv)
    for r in cdr_records:
        caller_id = f"PHONE:{r['caller']}"
        callee_id = f"PHONE:{r['callee']}"
        tower = r["tower_id"]
        ts = r["timestamp"]
        status = r.get("status", "Active")

        # Register BTS pings for co-location
        graph_service.register_tower_ping(r["caller"], tower, ts)
        graph_service.register_tower_ping(r["callee"], tower, ts)

        # Merge Phone Nodes
        db_manager.merge_node(caller_id, f"Tel: {r['caller']}", "Phone", {
            "phone_number": r["caller"],
            "status": status,
            "tower_id": tower,
            "last_active": ts,
            "sha256_hash": cdr_sha256
        })
        db_manager.merge_node(callee_id, f"Tel: {r['callee']}", "Phone", {
            "phone_number": r["callee"],
            "status": "Active",
            "tower_id": tower,
            "last_active": ts,
            "sha256_hash": cdr_sha256
        })

        # Merge COMMUNICATED_WITH Edge
        db_manager.merge_relationship(
            source_id=caller_id,
            target_id=callee_id,
            rel_type="COMMUNICATED_WITH",
            properties={
                "duration_sec": r.get("duration_sec", 60),
                "tower_id": tower,
                "timestamp": ts,
                "weight": 1.0 + min(r.get("duration_sec", 60) / 120.0, 3.0)
            }
        )

    print(f"  ✓ Ingested {len(cdr_records)} CDR logs across {len(set(r['tower_id'] for r in cdr_records))} BTS cell towers.")

    # 4. Ingest Financial Logs for Logistics Filter & Mule Transactions
    print(f"\n[3/4] Ingesting Financial Logs from {fin_csv} via Java/Pandas Bridge...")
    fin_sha256 = bsa_crypto.calculate_sha256_file(fin_csv)
    print(f"  🔒 SHA-256 Hash calculated immediately: {fin_sha256}")

    fin_records = java_bridge.parse_financial_file(fin_csv)
    for r in fin_records:
        sender_id = f"ACCOUNT:{r['sender']}" if not r['sender'].startswith("ACCOUNT:") and r['sender'].isdigit() else (f"ENTITY:{r['sender']}" if not r['sender'].startswith("ACCOUNT:") else r['sender'])
        receiver_id = f"ACCOUNT:{r['receiver']}" if not r['receiver'].startswith("ACCOUNT:") and r['receiver'].isdigit() else (f"ENTITY:{r['receiver']}" if not r['receiver'].startswith("ACCOUNT:") else r['receiver'])
        amount = r["amount"]
        category = r.get("category", "TRANSFER")
        merchant = r.get("merchant", "General")
        ts = r.get("timestamp", "")

        # Register for Logistics Filter evaluation
        graph_service.register_financial_tx(r["sender"], category, merchant, amount, ts)

        # Merge Account / Entity Nodes
        sender_type = "BankAccount" if sender_id.startswith("ACCOUNT:") else "Organization"
        receiver_type = "BankAccount" if receiver_id.startswith("ACCOUNT:") else "Organization"

        db_manager.merge_node(sender_id, r["sender"] if sender_type == "Organization" else f"A/C {r['sender']}", sender_type, {
            "account_number": r["sender"],
            "status": "Transacting",
            "sha256_hash": fin_sha256
        })
        db_manager.merge_node(receiver_id, r["receiver"] if receiver_type == "Organization" else f"A/C {r['receiver']}", receiver_type, {
            "account_number": r["receiver"],
            "status": "Transacting",
            "sha256_hash": fin_sha256
        })

        # Merge Edge
        edge_type = "TRANSFERRED_TO" if category == "TRANSFER" else category
        db_manager.merge_relationship(
            source_id=sender_id,
            target_id=receiver_id,
            rel_type=edge_type,
            properties={
                "amount": amount,
                "category": category,
                "merchant": merchant,
                "date": ts,
                "weight": 1.0 + min(amount / 200000.0, 5.0)
            }
        )

    print(f"  ✓ Ingested {len(fin_records)} financial log records.")

    # 5. Run Graph ML & Threat Detection
    print("\n[4/4] Running Graph ML: nx.betweenness_centrality, SIM Churn, Logistics & BTS Co-Location...")
    metrics = graph_service.compute_graph_metrics()

    # 6. Summary Report
    res = graph_service.get_d3_graph()
    summary = res.summary
    print("\n" + "=" * 70)
    print("INGESTION & THREAT DETECTION SUMMARY:")
    print(f"  • Total Nodes:           {summary.total_nodes}")
    print(f"  • Total Edges/Links:     {summary.total_links}")
    print(f"  • Suspects (Deduplicated):{summary.suspect_count}")
    print(f"  • Bank Accounts:         {summary.bank_account_count}")
    print(f"  • Phones Monitored:      {summary.phone_count}")
    print(f"  • Vehicles Tracked:      {summary.vehicle_count}")
    print(f"  • Locations:             {summary.location_count}")
    print(f"  • FIRs:                  {summary.fir_count}")
    print(f"  • High-Risk Entities:    {summary.high_risk_count}")
    print(f"  • Threat Alerts Active:  {summary.threat_alert_count}")
    print(f"  • BTS Co-Locations:      {summary.bts_colocation_count}")
    print(f"  • SIM Churn Continuties: {summary.sim_churn_count}")
    print(f"  • Traced Fraud Volume:   ₹{summary.total_fraud_volume:,.2f}")
    print(f"  • Registered Cryptos:    {len(bsa_crypto.list_registry())} files with Section 63(4) BSA Certs")
    print("=" * 70)

if __name__ == "__main__":
    run_ingestion()
