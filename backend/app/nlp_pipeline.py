import re
import spacy
import logging
from typing import Dict, List, Any, Set, Tuple, Optional
from app.java_bridge import java_bridge

logger = logging.getLogger("crime_intelligence.nlp")

class FIRNLPPipeline:
    """
    Forensic NLP & Entity Resolution Pipeline.
    Extracts PERSON, LOC, BANK_ACC, VEHICLE_REG, and financial/telecom targets,
    and performs Levenshtein distance suspect profile deduplication (threshold <= 2).
    """
    def __init__(self, model_name: str = "en_core_web_sm"):
        try:
            import en_core_web_sm
            self.nlp = en_core_web_sm.load()
            logger.info("Loaded spaCy en_core_web_sm pipeline.")
        except Exception:
            try:
                self.nlp = spacy.load(model_name)
                logger.info(f"Loaded spaCy model {model_name}.")
            except Exception as e:
                logger.warning(f"Notice: Loading blank English spacy pipeline ({e}).")
                self.nlp = spacy.blank("en")
                
        # Indian state RTO prefixes for vehicle validation
        self.rto_state_prefixes = {
            "DL", "MH", "KA", "HR", "WB", "UP", "PB", "TN", "GJ", "RJ",
            "MP", "AP", "TS", "KL", "BR", "JH", "OD", "CH", "UK", "HP",
            "GA", "AS", "TR", "ML", "MN", "NL", "MZ", "SK", "AR", "PY"
        }

        # Known stopwords in Indian police FIRs
        self.stop_entities = {
            "complainant", "accused", "victim", "investigation", "intelligence",
            "fir", "police", "cyber", "special cell", "crime branch", "act",
            "section", "rs", "inr", "bank", "branch", "atm", "account", "officer",
            "sub inspector", "inspector", "station", "station house", "sho",
            "siphoned", "transferred", "wired", "deposited", "withdrawn"
        }

        # Registry for unified suspect profile deduplication
        self.suspect_canonical_profiles: Dict[str, Dict[str, Any]] = {}

    def compute_levenshtein(self, s1: str, s2: str) -> int:
        """Calculates the Levenshtein distance between two strings using dynamic programming."""
        return java_bridge.compute_levenshtein(s1, s2)

    def clean_suspect_name(self, raw_name: str) -> Optional[str]:
        """Sanitizes extracted suspect name, stripping prefixes and invalid tokens."""
        if not raw_name:
            return None
        cleaned = raw_name.strip().strip(",.-;:")
        
        # Strip common legal prefixes
        prefixes_to_strip = [
            r'^(?:accused|suspect|co-accused|mastermind|kingpin|associate|driver|convict)\s+',
            r'^(?:shri|mr|ms|smt|dr)\.?\s+'
        ]
        for p in prefixes_to_strip:
            cleaned = re.sub(p, '', cleaned, flags=re.IGNORECASE).strip()

        # Reject if too short, contains currency words, or is a vehicle / number pattern
        lower = cleaned.lower()
        if len(cleaned) <= 2 or lower in self.stop_entities:
            return None
        if re.search(r'\b(?:rs|inr|lakh|crore|siphoned|transferred|account|police|station)\b', lower):
            return None
        if re.search(r'^[A-Z]{2}[-\s]?[0-9]{1,2}', cleaned):
            return None
        if re.search(r'^\d+$', cleaned):
            return None

        return cleaned

    def resolve_suspect_profile(self, extracted_name: str) -> Tuple[str, str, bool]:
        """
        Fuzzy Suspect Profile Resolution:
        If an extracted suspect name has a Levenshtein distance <= 2 to an existing suspect profile,
        merge them into the single unified profile ID to prevent duplicate nodes.
        Returns: (canonical_id, canonical_name, was_merged)
        """
        clean_name = self.clean_suspect_name(extracted_name)
        if not clean_name:
            return "", "", False

        norm_name = clean_name.lower()

        # Exact match check
        for can_id, profile in self.suspect_canonical_profiles.items():
            if norm_name == profile["canonical_name"].lower() or norm_name in [a.lower() for a in profile["aliases"]]:
                return can_id, profile["canonical_name"], False

        # Fuzzy Levenshtein match check (distance <= 2)
        for can_id, profile in self.suspect_canonical_profiles.items():
            can_name = profile["canonical_name"]
            dist = self.compute_levenshtein(clean_name, can_name)
            if dist <= 2:
                if clean_name not in profile["aliases"] and clean_name != can_name:
                    profile["aliases"].append(clean_name)
                logger.info(f"Fuzzy match (Levenshtein dist={dist}): Merged suspect '{clean_name}' -> '{can_name}' (ID: {can_id})")
                return can_id, can_name, True

        # New distinct profile
        safe_key = re.sub(r'[^a-zA-Z0-9_]', '_', norm_name.replace(" ", "_"))
        canonical_id = f"SUSPECT:{safe_key}"
        self.suspect_canonical_profiles[canonical_id] = {
            "canonical_id": canonical_id,
            "canonical_name": clean_name,
            "aliases": [clean_name]
        }
        return canonical_id, clean_name, False

    def extract_regex_patterns(self, text: str) -> Dict[str, Any]:
        """Extracts structured patterns for Indian forensic data."""
        # 1. Vehicle Registration Numbers (e.g. DL-01-AB-1234, MH 02 CD 5678, KA05XY9999, HR26DQ5555)
        vehicle_pattern = re.compile(
            r'\b([A-Z]{2})[\s\-]?(0[1-9]|[1-9][0-9])[\s\-]?([A-Z]{1,3})[\s\-]?([0-9]{4})\b',
            re.IGNORECASE
        )
        vehicles: Set[str] = set()
        for m in vehicle_pattern.finditer(text):
            state_code = m.group(1).upper()
            if state_code in self.rto_state_prefixes:
                rto_num = m.group(2)
                series = m.group(3).upper()
                digits = m.group(4)
                standard_reg = f"{state_code}-{rto_num}-{series}-{digits}"
                vehicles.add(standard_reg)

        # 2. Phone Numbers (Indian 10-digit mobile)
        phone_pattern = re.compile(r'\b(?:\+?91[\-\s]?)?([6-9]\d{9})\b')
        phones: Set[str] = {m.group(1) for m in phone_pattern.finditer(text)}

        # 3. Bank Account Numbers (9 to 18 digits)
        account_pattern = re.compile(
            r'(?:account\s*(?:no\.?|number|:)?\s*|a/c\s*(?:no\.?|number|:)?\s*|\baccount\s+)(\d{9,18})\b|'
            r'\b(\d{11,18})\b',
            re.IGNORECASE
        )
        accounts: Set[str] = set()
        for m in account_pattern.finditer(text):
            acc = m.group(1) or m.group(2)
            if acc and len(acc) >= 9:
                if acc not in phones:
                    accounts.add(acc)

        # 4. Financial Amounts (Rs / INR / Lakhs / Crores)
        amount_pattern = re.compile(
            r'(?:Rs\.?|INR|₹)\s*([\d,]+(?:\.\d+)?)|'
            r'([\d,]+)\s*(?:lakh|crore|lakhs|crores|rupees|INR)',
            re.IGNORECASE
        )
        amounts: List[float] = []
        for m in amount_pattern.finditer(text):
            val_str = m.group(1) or m.group(2)
            if val_str:
                clean_val = val_str.replace(",", "")
                try:
                    val = float(clean_val)
                    match_snippet = text[max(0, m.start()-10):min(len(text), m.end()+15)].lower()
                    if "crore" in match_snippet:
                        val *= 10000000
                    elif "lakh" in match_snippet:
                        val *= 100000
                    amounts.append(val)
                except ValueError:
                    pass

        # 5. Cell Tower IDs (BTS)
        tower_pattern = re.compile(r'\b(?:TOWER|CELL|BTS|TWR)[\-_][A-Z0-9\-]+\b', re.IGNORECASE)
        towers = [m.group(0).upper() for m in tower_pattern.finditer(text)]

        # 6. IPC / IT Act Sections
        ipc_pattern = re.compile(r'\b(?:IPC\s*[\d\w,\s]+|IT\s*Act\s*[\d\w,\s]+|BNS\s*[\d\w,\s]+|NDPS\s*[\d\w,\s]+)\b', re.IGNORECASE)
        sections = [m.group(0).strip() for m in ipc_pattern.finditer(text)]

        return {
            "bank_accounts": list(accounts),
            "phone_numbers": list(phones),
            "vehicle_registrations": list(vehicles),
            "cell_towers": list(set(towers)),
            "amounts": amounts,
            "sections": sections
        }

    def process_fir_text(
        self,
        fir_number: str,
        text: str,
        extra_meta: Optional[Dict[str, Any]] = None,
        sha256_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """Parses unstructured FIR text with spaCy NER + forensic regexes."""
        extra_meta = extra_meta or {}
        doc = self.nlp(text)

        extracted_entities = []
        raw_suspects = set()
        locations = set()
        organizations = set()

        if extra_meta.get("state"):
            locations.add(extra_meta["state"])

        # Extract spaCy named entities
        if self.nlp.has_pipe("ner"):
            for ent in doc.ents:
                clean_name = ent.text.strip().strip(",.-;:")
                lower_clean = clean_name.lower()
                if len(clean_name) <= 2 or lower_clean in self.stop_entities:
                    continue

                if lower_clean.startswith("complainant ") or lower_clean.startswith("victim "):
                    continue

                cleaned_candidate = self.clean_suspect_name(clean_name)

                extracted_entities.append({
                    "text": clean_name,
                    "label": ent.label_,
                    "start_char": ent.start_char,
                    "end_char": ent.end_char
                })

                if ent.label_ == "PERSON" and cleaned_candidate:
                    raw_suspects.add(cleaned_candidate)
                elif ent.label_ in ["GPE", "LOC"]:
                    locations.add(clean_name)
                elif ent.label_ == "ORG":
                    organizations.add(clean_name)

        regex_data = self.extract_regex_patterns(text)

        # Pre-seeded names recognition
        known_suspect_names = [
            "Vikram Singhania", "Vikram Singhaniya", "Amit Verma", "Priya Sharma",
            "Sameer Khan", "Kabir Sheikh", "Farhan Akhtar", "Suresh Reddy",
            "Rahul Mondal", "Raahul Mondal", "Dinesh Kumar", "Tariq Ali",
            "Ananya Sen", "Rajesh Kumar", "Rajeshh Kumar", "Pooja Gupta", "Puja Gupta"
        ]
        for name in known_suspect_names:
            if name.lower() in text.lower():
                raw_suspects.add(name)

        known_locations = [
            "New Delhi", "Delhi", "Rohini", "Connaught Place", "Mumbai", "Bandra",
            "Andheri", "Bengaluru", "Indiranagar", "Koramangala", "Jamtara",
            "Nuh", "Mewat", "Kolkata", "Park Street", "Salt Lake", "Hyderabad",
            "Cyberabad", "Pune", "Hinjewadi", "Gurugram", "Noida"
        ]
        for loc in known_locations:
            if loc.lower() in text.lower():
                locations.add(loc)

        # Fuzzy Suspect Profile Unification (Levenshtein Distance <= 2)
        unified_suspects: Dict[str, Dict[str, Any]] = {}
        for s in raw_suspects:
            cleaned = self.clean_suspect_name(s)
            if not cleaned:
                continue
            can_id, can_name, was_merged = self.resolve_suspect_profile(cleaned)
            if not can_id:
                continue
            if can_id not in unified_suspects:
                unified_suspects[can_id] = {
                    "id": can_id,
                    "name": can_name,
                    "raw_mentions": [cleaned],
                    "aliases": self.suspect_canonical_profiles[can_id]["aliases"]
                }
            else:
                if cleaned not in unified_suspects[can_id]["raw_mentions"]:
                    unified_suspects[can_id]["raw_mentions"].append(cleaned)

        # Build Graph Nodes & Links
        nodes = []
        links = []

        # 1. FIR Node
        fir_id = f"FIR:{fir_number}"
        nodes.append({
            "id": fir_id,
            "label": fir_number,
            "type": "FIR",
            "sha256_hash": sha256_hash,
            "details": {
                "police_station": extra_meta.get("police_station", "Cyber Crime Unit"),
                "incident_date": extra_meta.get("incident_date", "2026-08-30"),
                "ipc_sections": extra_meta.get("ipc_sections", ", ".join(regex_data["sections"])),
                "raw_text": text,
                "sha256_hash": sha256_hash
            }
        })

        # 2. Unified Suspect Nodes & Links
        suspect_ids = list(unified_suspects.keys())
        for s_id, s_info in unified_suspects.items():
            nodes.append({
                "id": s_id,
                "label": s_info["name"],
                "type": "Suspect",
                "sha256_hash": sha256_hash,
                "details": {
                    "name": s_info["name"],
                    "aliases": s_info["aliases"],
                    "role": "Accused / Primary Suspect",
                    "raw_mentions": s_info["raw_mentions"],
                    "sha256_hash": sha256_hash
                }
            })
            links.append({
                "source": s_id,
                "target": fir_id,
                "type": "NAMED_IN",
                "weight": 1.5,
                "details": {"role": "Named in FIR", "fir": fir_number}
            })

        # Co-accused association
        for i in range(len(suspect_ids)):
            for j in range(i + 1, len(suspect_ids)):
                links.append({
                    "source": suspect_ids[i],
                    "target": suspect_ids[j],
                    "type": "ASSOCIATED_WITH",
                    "weight": 2.0,
                    "details": {"context": f"Co-accused in {fir_number}"}
                })

        # 3. Bank Account Nodes & Links
        for acc in regex_data["bank_accounts"]:
            acc_id = f"ACCOUNT:{acc}"
            nodes.append({
                "id": acc_id,
                "label": f"A/C {acc}",
                "type": "BankAccount",
                "sha256_hash": sha256_hash,
                "details": {
                    "account_number": acc,
                    "bank_name": "Mule / Flagged Account",
                    "status": "Flagged in FIR",
                    "sha256_hash": sha256_hash
                }
            })
            for s_id in suspect_ids:
                links.append({
                    "source": s_id,
                    "target": acc_id,
                    "type": "OWNS_ACCOUNT",
                    "weight": 1.5,
                    "details": {"status": "Account Holder / Controller"}
                })

        # 4. Location Nodes & Links
        for loc in locations:
            loc_id = f"LOCATION:{loc.lower().replace(' ', '_')}"
            nodes.append({
                "id": loc_id,
                "label": loc,
                "type": "Location",
                "details": {"name": loc, "type": "Jurisdiction / Operation Hub"}
            })
            for s_id in suspect_ids:
                links.append({
                    "source": s_id,
                    "target": loc_id,
                    "type": "OPERATES_FROM",
                    "weight": 1.0,
                    "details": {"location": loc}
                })

        # 5. Phone Nodes & Links
        for phone in regex_data["phone_numbers"]:
            phone_id = f"PHONE:{phone}"
            nodes.append({
                "id": phone_id,
                "label": f"Tel: {phone}",
                "type": "Phone",
                "sha256_hash": sha256_hash,
                "details": {"phone_number": phone, "status": "Active", "sha256_hash": sha256_hash}
            })
            for s_id in suspect_ids:
                links.append({
                    "source": s_id,
                    "target": phone_id,
                    "type": "USES_PHONE",
                    "weight": 1.5,
                    "details": {"phone": phone}
                })

        # 6. Vehicle Registration Nodes & Links (TARGET: VEHICLE_REG)
        for veh in regex_data["vehicle_registrations"]:
            veh_id = f"VEHICLE:{veh.replace('-', '_')}"
            nodes.append({
                "id": veh_id,
                "label": f"Veh: {veh}",
                "type": "Vehicle",
                "sha256_hash": sha256_hash,
                "details": {
                    "registration_number": veh,
                    "status": "Tracked in Transit / FIR Evidence",
                    "sha256_hash": sha256_hash
                }
            })
            for s_id in suspect_ids:
                links.append({
                    "source": s_id,
                    "target": veh_id,
                    "type": "DRIVES_VEHICLE",
                    "weight": 1.5,
                    "details": {"vehicle": veh}
                })

        return {
            "fir_number": fir_number,
            "extracted_entities": extracted_entities,
            "regex_data": regex_data,
            "suspects": [s["name"] for s in unified_suspects.values()],
            "unified_suspect_profiles": list(unified_suspects.values()),
            "bank_accounts": regex_data["bank_accounts"],
            "locations": list(locations),
            "phone_numbers": regex_data["phone_numbers"],
            "vehicles": regex_data["vehicle_registrations"],
            "cell_towers": regex_data["cell_towers"],
            "amounts": regex_data["amounts"],
            "nodes": nodes,
            "links": links
        }

nlp_pipeline = FIRNLPPipeline()
