import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import db_manager

def initialize_database():
    print("=" * 60)
    print("Initializing Neo4j Graph Database Schema & Constraints...")
    print("=" * 60)
    
    status = db_manager.is_connected
    if status:
        print(f"✓ Connected to Neo4j database successfully.")
        res = db_manager.init_schema()
        print(f"✓ Applied {len(res['applied'])} constraints and indexes:")
        for c in res["applied"]:
            print(f"   -> {c}")
    else:
        print("! Note: Neo4j server is currently offline or unreachable.")
        print("  The application will automatically use its in-memory graph engine.")
        print("  To connect Neo4j natively, launch Neo4j Desktop or local Neo4j server")
        print("  and configure backend/.env with your credentials.")
    print("=" * 60)

if __name__ == "__main__":
    initialize_database()
