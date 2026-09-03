# NEXUS GRAPH v2.0: AI Crime, Telecom & Financial Threat Intelligence

An end-to-end intelligence graph and cybercrime analysis system conforming to Section 63(4) of the **Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023)**. Ingests unstructured First Information Reports (FIRs), Call Detail Records (CDRs), and financial logs via **spaCy NLP** and **Java OOP / Pandas bulk I/O**, models them in an in-memory **NetworkX** graph engine, computes **Betweenness Centrality broker influence risk scores**, and visualizes them on a responsive **D3.js Sky Blue SVG Canvas + Bootstrap 5** forensic investigation dashboard.

---

## 🏛️ System Architecture & 5-Phase Blueprint

```mermaid
graph TD
    subgraph Phase 1: Ingestion & Fuzzy Resolution
        A[Raw FIR Text, CDR CSVs, Financial Logs] -->|Instant Hash| H[SHA-256 Hash Registry]
        A --> B[Java Bulk Data Processor / Pandas Streamer]
        B --> C[spaCy NER + Forensic Regex Pipeline]
        C -->|TARGETS: PERSON, LOC, BANK_ACC, VEHICLE_REG| D[Levenshtein Distance Engine]
        D -->|Distance <= 2 Merge: Rahul == Raahul| E[Unified Suspect Profiles]
    end

    subgraph Phase 2 & 4: NetworkX Graph & Algorithmic Threat Detection
        E --> G[(In-Memory NetworkX Graph)]
        G --> T1[SIM Churn: Bipartite Matching >= 85% Target Overlap]
        G --> T2[Logistics Filter: Transit Purchases + Frequent Short Hotel Stays]
        G --> T3[BTS Co-Location: Time-Window Grouping <= 10m Cell Tower Pings]
        T1 --> G
        T2 --> G
        T3 --> G
        G --> ML[nx.betweenness_centrality -> centrality_score]
    end

    subgraph Phase 3 & 5: Legal Cryptography & Sky Blue D3 Interface
        H --> BSA[Section 63 4 BSA 2023 Two-Part PDF Certificate Generator]
        G --> API[/api/network: nodes & links]
        API --> UI[D3.js Force Simulation on Sky Blue SVG Canvas]
        UI -->|Dynamic Node Radius| RAD[Scaled by centrality_score]
        UI -->|Node Click Event| SP[Bootstrap 5 Side Panel: Evidence + SHA-256 Seal]
        BSA --> PDF[Download Part A & Part B Court PDF]
    end
```

---

## 🚀 Key Modules & Capabilities

### Phase 1: Ingestion & Fuzzy Resolution (Backend)
- **Multi-Source Ingestion**: Ingests structured Call Detail Records (CDRs), financial transaction logs, and unstructured FIR narratives via Pandas and Java Object-Oriented streaming classes (`BulkDataProcessor.java`).
- **Target Entity Extraction**: Custom spaCy pipeline extracting `PERSON` (Accused & Suspects), `LOC` (Jurisdictions & Hubs), `BANK_ACC` (9–18 digit mule accounts), and `VEHICLE_REG` (Indian vehicle registration plates, e.g., `DL-01-AB-1234`, `MH-02-CD-5678`, `KA-05-XY-9999`, `WB-02-AK-9876`).
- **Levenshtein Distance Deduplication**: Dynamic programming matrix calculating string edit distance. If suspect names have a distance $\le 2$ (e.g., *"Rahul"* and *"Raahul"*, *"Vikram Singhania"* and *"Vikram Singhaniya"*), they are automatically merged into a single unified profile ID to eliminate duplicate nodes.

### Phase 2: The Graph Mapping Engine
- **In-Memory NetworkX Engine**: Models multi-relational graphs linking Suspects, Phones, Bank Accounts, Vehicles, Locations, and FIRs with weighted edges (`TRANSFERRED_TO`, `COMMUNICATED_WITH`, `USES_PHONE`, `DRIVES_VEHICLE`, `CO_LOCATED`, `SIM_CHURN_CONTINUITY`).
- **Betweenness Centrality**: Executes `nx.betweenness_centrality()` to calculate broker influence, assigning the resulting float value to each node's `centrality_score` attribute.

### Phase 3: Legal Cryptography (BSA 2023 Compliance)
- **Instant Ingestion Hashing**: Immediate calculation of `hashlib.sha256()` across all raw CSVs and text payloads upon receipt.
- **Section 63(4) BSA 2023 Two-Part PDF Certificates**:
  - **Part A**: Declaration by System Operator / Ingestion Officer (details of electronic machine, OS, lawful custody, and software version under Sec 63(4)(a)).
  - **Part B**: Certification by Independent Forensic Examiner (cryptographic SHA-256 match confirmation and 0% collision verification under Sec 63(4)(b)).
  - Explicitly renders the calculated SHA-256 alphanumeric digest string and forensic stamp for legal judicial admissibility.

### Phase 4: Algorithmic Threat Detection (Women's Safety & Syndicate Tracking)
- **SIM Churn Tracking**: Bipartite target overlap matching. If a phone number is deactivated, scans the network for newly activated lines whose outbound contacts overlap by $\ge 85\%$. Automatically marks `alert: true` and creates a `SIM_CHURN_CONTINUITY` link.
- **Logistics Filter (Women's Safety)**: Scans financial transactions to flag entities executing repetitive transit ticket purchases (IRCTC, RedBus, MakeMyTrip, cab) alongside high-frequency, short-duration hotel bookings (OYO, Treebo, Ginger).
- **BTS Co-Location Engine**: Time-window grouping function detecting if two distinct phones ping the identical cell tower ID within a $\le 10$-minute threshold, generating a `CO_LOCATED` edge with time-delta metadata.

### Phase 5: D3.js Frontend Execution
- **REST Endpoint `/api/network`**: Returns JSON payload structured with `nodes` and `links` arrays conforming to D3 force simulation standards.
- **D3.js Force Simulation**: Integrates `d3.forceSimulation()`, `d3.forceManyBody()` repulsion, `d3.forceLink()`, and collision avoidance.
- **Strictly Sky Blue Canvas**: SVG canvas background strictly set to `#87CEEB` (Sky Blue).
- **Dynamic Circle Radius**: Circle radii dynamically scale based on the `centrality_score` attribute.
- **Forensic Side Panel**: `.on("click")` event listener injecting raw narrative evidence, cell tower logs, transit logs, and cryptographic SHA-256 hash with one-click BSA certificate generation.

---

## 📁 Directory Structure

```
sih project/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                  # FastAPI REST API (/api/network, /api/bsa-certificate)
│   │   ├── database.py              # Neo4j & NetworkX fallback connection manager
│   │   ├── nlp_pipeline.py          # spaCy NER + Levenshtein fuzzy deduplication
│   │   ├── graph_service.py         # NetworkX betweenness centrality & threat detection
│   │   ├── bsa_crypto.py            # SHA-256 hasher & Section 63(4) BSA PDF certificate engine
│   │   ├── java_bridge.py           # Java OOP processor bridge & fallback
│   │   ├── java_io/
│   │   │   └── BulkDataProcessor.java # Java bulk I/O streaming parser
│   │   ├── models.py                # Pydantic data schemas
│   │   └── mock_data_generator.py   # Synthetic FIR, CDR, and financial dataset generator
│   ├── data/
│   │   ├── mock_firs.csv            # Unstructured FIRs with VEHICLE_REG and name variants
│   │   ├── mock_cdr.csv             # CDR telecom logs with BTS cell tower IDs & SIM churn
│   │   └── mock_financial_logs.csv  # Financial logs with transit & hotel booking patterns
│   ├── scripts/
│   │   └── ingest_data.py           # Batch ingestion & threat ML runner
│   ├── tests/
│   │   ├── test_bsa_pipeline.py     # Unit tests for Levenshtein, Centrality, and BSA Certs
│   │   └── test_api_endpoints.py    # Integration tests for /api/network & PDF endpoints
│   └── requirements.txt             # Python dependencies
├── frontend/
│   ├── index.html                   # Bootstrap 5 Dashboard with Sky Blue D3 container
│   ├── css/
│   │   └── style.css                # Sky Blue canvas styling & threat halo animations
│   └── js/
│       ├── app.js                   # Application state, API integration & side-panel populator
│       └── graph.js                 # D3.js v7 force simulation with dynamic centrality sizing
├── run.sh                           # One-click startup script
└── README.md                        # Documentation
```

---

## ⚡ Quickstart & Verification

### 1. Launch System
```bash
./run.sh
```
Or run directly:
```bash
backend/venv/bin/uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --reload
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser.

### 2. Run Test Suite
```bash
backend/venv/bin/python -m unittest discover -s backend/tests -p "test_*.py"
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/network` | Primary D3 graph payload with `nodes` (with `centrality_score`, `alert`, `sha256_hash`) and `links` |
| `GET` | `/api/bsa-certificate/download` | Outputs official Two-Part Section 63(4) BSA 2023 PDF Certificate for any SHA-256 hash |
| `GET` | `/api/bsa-certificate/list` | Lists all cryptographically sealed evidence files and SHA-256 hashes |
| `GET` | `/api/threats` | Summarizes SIM Churn events, BTS Co-locations, and Logistics Alerts |
| `POST` | `/api/analyze-fir` | On-the-fly NLP extraction, vehicle parsing, instant SHA-256 hash, and fuzzy suspect deduplication |
| `GET` | `/api/algorithms/recompute` | Explicitly recomputes Betweenness Centrality and Threat Detection algorithms |
