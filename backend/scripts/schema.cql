// ==============================================================================
// Neo4j Cypher Graph Schema: Crime & Financial Network Intelligence
// Establishing Distinct Constraints to Prevent Duplication
// ==============================================================================

// --- Uniqueness Constraints (Neo4j 4.4+ / 5.x) ---

// 1. Suspect Unique Constraint (By suspect ID / canonical name)
CREATE CONSTRAINT suspect_id_unique IF NOT EXISTS
FOR (s:Suspect) REQUIRE s.id IS UNIQUE;

CREATE CONSTRAINT suspect_name_unique IF NOT EXISTS
FOR (s:Suspect) REQUIRE s.name IS UNIQUE;

// 2. Bank Account Unique Constraint (By Account Number)
CREATE CONSTRAINT bank_account_unique IF NOT EXISTS
FOR (b:BankAccount) REQUIRE b.account_number IS UNIQUE;

// 3. Location Unique Constraint (By Location / City Name)
CREATE CONSTRAINT location_name_unique IF NOT EXISTS
FOR (l:Location) REQUIRE l.name IS UNIQUE;

// 4. FIR Unique Constraint (By FIR Case Number)
CREATE CONSTRAINT fir_number_unique IF NOT EXISTS
FOR (f:FIR) REQUIRE f.fir_number IS UNIQUE;

// 5. Phone / Communication Node Unique Constraint
CREATE CONSTRAINT phone_number_unique IF NOT EXISTS
FOR (p:Phone) REQUIRE p.phone_number IS UNIQUE;

// 6. Organization / Shell Entity Unique Constraint
CREATE CONSTRAINT org_name_unique IF NOT EXISTS
FOR (o:Organization) REQUIRE o.name IS UNIQUE;

// --- Performance Indexes ---

CREATE INDEX suspect_risk_idx IF NOT EXISTS
FOR (s:Suspect) ON (s.risk_score);

CREATE INDEX bank_risk_idx IF NOT EXISTS
FOR (b:BankAccount) ON (b.risk_score);

CREATE INDEX fir_date_idx IF NOT EXISTS
FOR (f:FIR) ON (f.incident_date);

CREATE INDEX location_state_idx IF NOT EXISTS
FOR (l:Location) ON (l.state);
