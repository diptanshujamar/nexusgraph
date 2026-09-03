import os
import csv
from typing import Dict, List, Any

def generate_mock_files(data_dir: str):
    """
    Generates realistic datasets for Nexus Graph:
    1. mock_firs.csv: Unstructured FIR texts with VEHICLE_REG, BANK_ACC, PERSON, LOC, and Levenshtein name variants.
    2. mock_cdr.csv: Call Detail Records with cell tower IDs, timestamps, and SIM churn events.
    3. mock_financial_logs.csv: Financial transaction logs with transit purchases & hotel bookings for logistics threat filtering.
    4. mock_transactions.csv: Traditional mule account transaction streams.
    """
    os.makedirs(data_dir, exist_ok=True)

    # 1. Mock FIRs CSV
    firs_path = os.path.join(data_dir, "mock_firs.csv")
    firs_data = [
        {
            "fir_number": "FIR-2026-DEL-101",
            "police_station": "Special Cell Cyber Crime, Lodhi Colony, New Delhi",
            "incident_date": "2026-08-10",
            "state": "Delhi",
            "ipc_sections": "BNS 318(4), 319(2), IT Act 66D",
            "raw_text": "FIR lodged on complaint of extortion and cyber syndicate operation. Suspect Vikram Singhania operating getaway vehicle registration DL-01-AB-1234 was observed coordinating with Amit Verma at Connaught Place, New Delhi. Siphoned Rs 45,00,000 into mule account 918234509122 at ICICI Bank. Vikram Singhania utilized primary mobile 9810011223 connected to tower TOWER-DEL-402."
        },
        {
            "fir_number": "FIR-2026-DEL-102",
            "police_station": "Crime Branch, Rohini Sector 3, Delhi",
            "incident_date": "2026-08-14",
            "state": "Delhi",
            "ipc_sections": "BNS 318(4), IT Act 66C",
            "raw_text": "Interception report against interstate syndicate. Suspect Vikram Singhaniya along with associate Priya Sharma transferred Rs 18,50,000 to account 550192837461. Suspect was spotted driving car with registration DL-01-AB-1234 near Rohini. Associate used phone 9811099887."
        },
        {
            "fir_number": "FIR-2026-MUM-204",
            "police_station": "Cyber Police Station, BKC, Mumbai",
            "incident_date": "2026-08-18",
            "state": "Maharashtra",
            "ipc_sections": "BNS 318, 111 (Organized Crime), IT Act 66D",
            "raw_text": "High-value corporate BEC cyber heist. Accused Tariq Ali routed Rs 75,00,000 through multiple mule accounts. Tariq Ali wired Rs 30,00,000 to Sameer Khan (Account: 440192837461) at Bandra, Mumbai and Rs 25,00,000 to Kabir Sheikh in Kolkata. Accused Tariq Ali was tracked in SUV vehicle registration MH-02-CD-5678 and mobile 9820099881 near cell tower TOWER-MUM-881."
        },
        {
            "fir_number": "FIR-2026-BLR-305",
            "police_station": "Cyber Economic Offences, Indiranagar, Bengaluru",
            "incident_date": "2026-08-22",
            "state": "Karnataka",
            "ipc_sections": "BNS 318(4), IT Act 66D",
            "raw_text": "Investigation into loan app extortion network. Suspect Rahul Mondal and co-accused Dinesh Kumar coerced victims into depositing Rs 22,00,000 into SBI account 309182746519. Rahul Mondal was operating with vehicle KA-05-XY-9999 from Koramangala, Bengaluru using phone 9845012345."
        },
        {
            "fir_number": "FIR-2026-BLR-306",
            "police_station": "STF Cyber Cell, Bengaluru",
            "incident_date": "2026-08-25",
            "state": "Karnataka",
            "ipc_sections": "BNS 318(4), 336(3)",
            "raw_text": "Follow-up charge against cyber syndicate. Accused Raahul Mondal was tracked receiving funds of Rs 14,00,000 in account 771920384756 from Dinesh Kumar. Suspect Raahul Mondal drove sedan vehicle KA-05-XY-9999 in Indiranagar, Bengaluru."
        },
        {
            "fir_number": "FIR-2026-KOL-408",
            "police_station": "Special Task Force, Salt Lake, Kolkata",
            "incident_date": "2026-08-28",
            "state": "West Bengal",
            "ipc_sections": "BNS 111, IT Act 66D, 84C",
            "raw_text": "Cross-border human trafficking and Hawala network intelligence. Syndicate boss Kabir Sheikh coordinated with Farhan Akhtar in Kolkata. Transferred Rs 60,00,000 across account 220193847561 and account 881920394857 held by Ananya Sen. Suspect Farhan Akhtar operated vehicle WB-02-AK-9876 and mobile 9830077665."
        }
    ]

    with open(firs_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["fir_number", "police_station", "incident_date", "state", "ipc_sections", "raw_text"])
        writer.writeheader()
        writer.writerows(firs_data)

    # 2. Mock CDR (Call Detail Records) CSV
    cdr_path = os.path.join(data_dir, "mock_cdr.csv")
    cdr_data = [
        # BTS Co-Location Cluster 1: Delhi TOWER-DEL-402 (within 4 minutes of each other)
        {"caller": "9810011223", "callee": "9811099887", "tower_id": "TOWER-DEL-402", "timestamp": "2026-08-10 14:02:10", "duration_sec": 180, "status": "Active"},
        {"caller": "9811099887", "callee": "9845012345", "tower_id": "TOWER-DEL-402", "timestamp": "2026-08-10 14:05:45", "duration_sec": 95, "status": "Active"},
        
        # BTS Co-Location Cluster 2: Mumbai TOWER-MUM-881 (within 6 minutes)
        {"caller": "9820099881", "callee": "9821144332", "tower_id": "TOWER-MUM-881", "timestamp": "2026-08-18 21:10:00", "duration_sec": 240, "status": "Deactivated"},
        {"caller": "9821144332", "callee": "9830077665", "tower_id": "TOWER-MUM-881", "timestamp": "2026-08-18 21:15:30", "duration_sec": 310, "status": "Active"},
        
        # SIM Churn Scenario:
        # Deactivated Phone: 9820099881 called [9821144332, 9810011223, 9830077665, 9845012345]
        {"caller": "9820099881", "callee": "9810011223", "tower_id": "TOWER-MUM-881", "timestamp": "2026-08-18 21:30:00", "duration_sec": 120, "status": "Deactivated"},
        {"caller": "9820099881", "callee": "9830077665", "tower_id": "TOWER-MUM-881", "timestamp": "2026-08-18 21:45:00", "duration_sec": 210, "status": "Deactivated"},
        {"caller": "9820099881", "callee": "9845012345", "tower_id": "TOWER-MUM-881", "timestamp": "2026-08-18 22:00:00", "duration_sec": 150, "status": "Deactivated"},

        # Newly Activated Replacement Phone: 9899011222 called the EXACT SAME 4 targets (100% overlap >= 85%)
        {"caller": "9899011222", "callee": "9821144332", "tower_id": "TOWER-MUM-901", "timestamp": "2026-08-20 09:15:00", "duration_sec": 190, "status": "Active"},
        {"caller": "9899011222", "callee": "9810011223", "tower_id": "TOWER-MUM-901", "timestamp": "2026-08-20 09:30:00", "duration_sec": 220, "status": "Active"},
        {"caller": "9899011222", "callee": "9830077665", "tower_id": "TOWER-MUM-901", "timestamp": "2026-08-20 10:00:00", "duration_sec": 140, "status": "Active"},
        {"caller": "9899011222", "callee": "9845012345", "tower_id": "TOWER-MUM-901", "timestamp": "2026-08-20 10:45:00", "duration_sec": 175, "status": "Active"},

        # BTS Co-Location Cluster 3: Kolkata TOWER-KOL-109 (within 3 minutes)
        {"caller": "9830077665", "callee": "9831122334", "tower_id": "TOWER-KOL-109", "timestamp": "2026-08-28 17:30:00", "duration_sec": 110, "status": "Active"},
        {"caller": "9831122334", "callee": "9845012345", "tower_id": "TOWER-KOL-109", "timestamp": "2026-08-28 17:32:45", "duration_sec": 180, "status": "Active"}
    ]

    with open(cdr_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["caller", "callee", "tower_id", "timestamp", "duration_sec", "status"])
        writer.writeheader()
        writer.writerows(cdr_data)

    # 3. Mock Financial Logs CSV (Logistics Filter: Transit + Hotel Bookings)
    fin_logs_path = os.path.join(data_dir, "mock_financial_logs.csv")
    fin_logs_data = [
        # Threat Flagged Entity: Tariq Ali / 440192837461 (Multiple IRCTC/RedBus + Frequent OYO/Treebo hotel bookings)
        {"from_account": "440192837461", "to_account": "IRCTC_CORP_01", "amount": 4200.0, "category": "TRANSIT_TICKET", "merchant": "IRCTC Train Booking Delhi-Mumbai", "date": "2026-08-15 08:30:00"},
        {"from_account": "440192837461", "to_account": "OYO_HOTELS_HQ", "amount": 3500.0, "category": "HOTEL_BOOKING", "merchant": "OYO Flagship 241 Rohini Delhi", "date": "2026-08-15 14:00:00"},
        {"from_account": "440192837461", "to_account": "REDBUS_INDIA", "amount": 2800.0, "category": "TRANSIT_TICKET", "merchant": "RedBus Sleeper Delhi-Jaipur", "date": "2026-08-17 19:45:00"},
        {"from_account": "440192837461", "to_account": "TREEBO_STAYS", "amount": 4100.0, "category": "HOTEL_BOOKING", "merchant": "Treebo Trend Jaipur Central", "date": "2026-08-18 01:15:00"},
        {"from_account": "440192837461", "to_account": "MAKEMYTRIP_AIR", "amount": 8900.0, "category": "AIR_TICKET", "merchant": "MakeMyTrip Flight Jaipur-Kolkata", "date": "2026-08-20 06:10:00"},
        {"from_account": "440192837461", "to_account": "GINGER_HOTELS", "amount": 5200.0, "category": "HOTEL_BOOKING", "merchant": "Ginger Hotel Salt Lake Kolkata", "date": "2026-08-20 12:30:00"},

        # High-value Mule Transfers
        {"from_account": "918234509122", "to_account": "550192837461", "amount": 1850000.0, "category": "TRANSFER", "merchant": "Inter-bank Layering", "date": "2026-08-11 11:20:00"},
        {"from_account": "550192837461", "to_account": "309182746519", "amount": 1200000.0, "category": "TRANSFER", "merchant": "Hawala Settlement", "date": "2026-08-15 16:40:00"},
        {"from_account": "440192837461", "to_account": "220193847561", "amount": 2500000.0, "category": "TRANSFER", "merchant": "Syndicate Payout", "date": "2026-08-19 18:10:00"},
        {"from_account": "220193847561", "to_account": "881920394857", "amount": 2000000.0, "category": "TRANSFER", "merchant": "Layering Node", "date": "2026-08-22 13:00:00"},
        {"from_account": "309182746519", "to_account": "771920384756", "amount": 1400000.0, "category": "TRANSFER", "merchant": "Final Cashout", "date": "2026-08-26 10:15:00"}
    ]

    with open(fin_logs_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["from_account", "to_account", "amount", "category", "merchant", "date"])
        writer.writeheader()
        writer.writerows(fin_logs_data)

    # 4. Standard Mock Transactions CSV (backward compatibility)
    tx_path = os.path.join(data_dir, "mock_transactions.csv")
    with open(tx_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["from_account", "to_account", "amount", "date", "type"])
        writer.writeheader()
        for r in fin_logs_data:
            writer.writerow({
                "from_account": r["from_account"],
                "to_account": r["to_account"],
                "amount": r["amount"],
                "date": r["date"],
                "type": r["category"]
            })

    print(f"Generated complete synthetic forensic datasets in {data_dir}")

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.abspath(os.path.join(current_dir, "..", "data"))
    generate_mock_files(data_dir)
