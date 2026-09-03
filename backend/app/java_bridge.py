import os
import sys
import json
import shutil
import logging
import subprocess
from typing import Dict, List, Any, Optional

logger = logging.getLogger("crime_intelligence.java_bridge")

class JavaBridge:
    """
    Java Object-Oriented Processing Bridge for bulk file I/O operations,
    Levenshtein distance calculation, and SHA-256 evaluation.
    Provides automated compilation and execution if JVM is present,
    with an optimized high-throughput Python fallback.
    """
    def __init__(self):
        self.java_available = shutil.which("java") is not None
        self.javac_available = shutil.which("javac") is not None
        self.compiled = False
        self.java_dir = os.path.dirname(os.path.abspath(__file__))
        self.java_io_dir = os.path.join(self.java_dir, "java_io")
        self.class_name = "app.java_io.BulkDataProcessor"
        self._init_java()

    def _init_java(self):
        if self.java_available and self.javac_available:
            java_src = os.path.join(self.java_io_dir, "BulkDataProcessor.java")
            if os.path.exists(java_src):
                try:
                    # Compile BulkDataProcessor
                    cmd = ["javac", "-d", self.java_dir, java_src]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if res.returncode == 0:
                        self.compiled = True
                        logger.info("Java BulkDataProcessor compiled successfully.")
                    else:
                        logger.warning(f"Java compilation note: {res.stderr}")
                except Exception as e:
                    logger.warning(f"Java init bypassed: {e}")

    def run_java_command(self, command: str, *args) -> Optional[Dict[str, Any]]:
        if not (self.java_available and self.compiled):
            return None
        try:
            cmd = ["java", "-cp", self.java_dir, self.class_name, command, *args]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                return json.loads(res.stdout.strip())
        except Exception as e:
            logger.debug(f"Java execution fallback: {e}")
        return None

    def compute_levenshtein(self, s1: str, s2: str) -> int:
        """Computes Levenshtein distance using Java if available, else native Python."""
        res = self.run_java_command("levenshtein", s1, s2)
        if res and "distance" in res:
            return int(res["distance"])

        # Native dynamic programming matrix
        return self._python_levenshtein(s1, s2)

    @staticmethod
    def _python_levenshtein(s1: str, s2: str) -> int:
        if s1 is None: s1 = ""
        if s2 is None: s2 = ""
        a, b = s1.strip().lower(), s2.strip().lower()
        if a == b: return 0
        if not a: return len(b)
        if not b: return len(a)

        len_a, len_b = len(a), len(b)
        dp = [list(range(len_b + 1))] + [[i] + [0] * len_b for i in range(1, len_a + 1)]

        for i in range(1, len_a + 1):
            for j in range(1, len_b + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                dp[i][j] = min(
                    dp[i - 1][j] + 1,      # deletion
                    dp[i][j - 1] + 1,      # insertion
                    dp[i - 1][j - 1] + cost # substitution
                )
        return dp[len_a][len_b]

    def parse_cdr_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Fast bulk streaming of CDR records via Java OOP parser or Python streaming."""
        res = self.run_java_command("parse-cdr", file_path)
        if res and "records" in res:
            return res["records"]

        import pandas as pd
        df = pd.read_csv(file_path)
        records = []
        for _, row in df.iterrows():
            records.append({
                "caller": str(row.get("caller", "")).strip(),
                "callee": str(row.get("callee", "")).strip(),
                "tower_id": str(row.get("tower_id", "UNKNOWN")).strip(),
                "timestamp": str(row.get("timestamp", "")).strip(),
                "duration_sec": int(row.get("duration_sec", 60) if pd.notna(row.get("duration_sec")) else 60),
                "status": str(row.get("status", "Active")).strip()
            })
        return records

    def parse_financial_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Fast bulk streaming of Financial records via Java OOP parser or Python streaming."""
        res = self.run_java_command("parse-financial", file_path)
        if res and "records" in res:
            return res["records"]

        import pandas as pd
        df = pd.read_csv(file_path)
        records = []
        for _, row in df.iterrows():
            records.append({
                "sender": str(row.get("from_account", row.get("sender", ""))).strip(),
                "receiver": str(row.get("to_account", row.get("receiver", ""))).strip(),
                "amount": float(row.get("amount", 0.0) if pd.notna(row.get("amount")) else 0.0),
                "category": str(row.get("category", row.get("type", "TRANSFER"))).strip(),
                "merchant": str(row.get("merchant", "General")).strip(),
                "timestamp": str(row.get("timestamp", row.get("date", ""))).strip()
            })
        return records

java_bridge = JavaBridge()
