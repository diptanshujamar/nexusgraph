from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class Node(BaseModel):
    id: str
    label: str
    type: str  # Suspect, BankAccount, Location, FIR, Phone, Vehicle, Organization
    centrality_score: float = 0.0  # nx.betweenness_centrality score
    risk_score: float = 0.0
    pagerank: float = 0.0
    degree: int = 0
    community: int = 0
    alert: bool = False
    alert_reasons: List[str] = Field(default_factory=list)
    sha256_hash: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

class Link(BaseModel):
    id: Optional[str] = None
    source: str
    target: str
    type: str  # TRANSFERRED_TO, ASSOCIATED_WITH, OPERATES_FROM, NAMED_IN, COMMUNICATED_WITH, OWNS_ACCOUNT, DRIVES_VEHICLE, CO_LOCATED, SIM_CHURN_CONTINUITY
    weight: float = 1.0
    amount: Optional[float] = None
    details: Dict[str, Any] = Field(default_factory=dict)

class GraphSummary(BaseModel):
    total_nodes: int = 0
    total_links: int = 0
    suspect_count: int = 0
    bank_account_count: int = 0
    location_count: int = 0
    fir_count: int = 0
    phone_count: int = 0
    vehicle_count: int = 0
    high_risk_count: int = 0
    threat_alert_count: int = 0
    bts_colocation_count: int = 0
    sim_churn_count: int = 0
    total_fraud_volume: float = 0.0
    neo4j_connected: bool = False

class GraphResponse(BaseModel):
    nodes: List[Node]
    links: List[Link]
    summary: GraphSummary

class FIRInput(BaseModel):
    fir_number: str
    police_station: str = "Cyber Crime PS"
    incident_date: str = "2026-08-30"
    text: str
    state: str = "Delhi"

class FileUploadRequest(BaseModel):
    filename: str
    file_type: str  # fir_csv, cdr_csv, financial_csv, or fir_text
    content: str    # Raw CSV or text content

class ExtractedEntity(BaseModel):
    text: str
    label: str
    start_char: int
    end_char: int

class FIRAnalysisResponse(BaseModel):
    fir_number: str
    sha256_hash: str
    extracted_entities: List[ExtractedEntity]
    extracted_suspects: List[str]
    extracted_bank_accounts: List[str]
    extracted_locations: List[str]
    extracted_vehicles: List[str]
    extracted_amounts: List[float]
    extracted_phones: List[str]
    nodes_added: int
    links_added: int
    message: str

class NodeDetailResponse(BaseModel):
    id: str
    label: str
    type: str
    centrality_score: float
    risk_score: float
    pagerank: float
    degree: int
    community: int
    alert: bool
    alert_reasons: List[str]
    sha256_hash: Optional[str] = None
    details: Dict[str, Any]
    neighbors: List[Dict[str, Any]]
    related_evidence: List[Dict[str, Any]]

class BSACertificateRequest(BaseModel):
    sha256_hash: str
    case_reference: str = "CR-2026-HQ-INTEL"
    operator_name: str = "Insp. R. K. Verma"
    operator_designation: str = "System Operator & Ingestion In-Charge"
    expert_name: str = "Dr. Ananya Ray"
    expert_designation: str = "Senior Cyber Forensic Examiner (CERT-In Empanelled)"
    file_description: Optional[str] = None

class HeatmapPoint(BaseModel):
    city: str
    lat: float
    lng: float
    intensity: float
    fir_count: int
    suspect_count: int
    fraud_volume: float
    high_risk: bool

class HeatmapTower(BaseModel):
    tower_id: str
    city: str
    lat: float
    lng: float
    call_pings: int
    colocated_alerts: int
    phones: List[str]

class HeatmapCorridor(BaseModel):
    name: str
    from_city: str
    to_city: str
    from_coords: List[float]
    to_coords: List[float]
    transit_mode: str
    hotel_stays: int
    alert: bool

class HeatmapResponse(BaseModel):
    points: List[HeatmapPoint]
    towers: List[HeatmapTower]
    corridors: List[HeatmapCorridor]
    summary: Dict[str, Any]

class SuspectAgeImpact(BaseModel):
    suspect_name: str
    canonical_id: str
    primary_crime: str
    age_18_25: int
    age_26_35: int
    age_36_50: int
    age_50_plus: int
    total_victims: int
    total_loss: float
    primary_target_group: str

class GenderCrimeImpact(BaseModel):
    crime_category: str
    male_victims: int
    female_victims: int
    other_victims: int
    total_victims: int
    female_percentage: float
    primary_vulnerability: str

class DemographicsResponse(BaseModel):
    suspect_age_matrix: List[SuspectAgeImpact]
    gender_crime_matrix: List[GenderCrimeImpact]
    age_group_summary: Dict[str, Any]
    gender_summary: Dict[str, Any]
    kpis: Dict[str, Any]

class APBBroadcastRequest(BaseModel):
    suspect_id: Optional[str] = None
    priority_level: str = "FLASH_RED_ALERT"
    originating_officer: str = "Insp. R. K. Verma, Ingestion In-Charge"
    case_reference: str = "CR-2026-HQ-INTEL"
    selected_stations: Optional[List[str]] = None
    include_vehicles: bool = True
    include_bank_accounts: bool = True
    include_phones: bool = True

class PoliceStationDispatch(BaseModel):
    station_name: str
    state: str
    jurisdiction: str
    status: str = "TRANSMITTED"
    timestamp: str
    latency_ms: int

class APBBroadcastResponse(BaseModel):
    broadcast_id: str
    cctns_reference: str
    suspect_name: str
    suspect_id: str
    aliases: List[str]
    vehicles: List[str]
    bank_accounts: List[str]
    phones: List[str]
    centrality_score: float
    threat_flags: List[str]
    sha256_hash: str
    timestamp: str
    dispatched_stations: List[PoliceStationDispatch]
    message: str
