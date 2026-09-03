package app.java_io;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * BulkDataProcessor: High-Performance Object-Oriented Java Bulk File I/O Engine.
 * Provides structured streaming parsers for CDRs, Financial Transaction Logs, and FIR Narratives,
 * integrated with cryptographic SHA-256 calculation and Levenshtein distance evaluation.
 */
public class BulkDataProcessor {

    // --- Record Models (OOP Encapsulation) ---

    public static class CDRRecord {
        private final String caller;
        private final String callee;
        private final String towerId;
        private final String timestamp;
        private final int durationSec;
        private final String status;

        public CDRRecord(String caller, String callee, String towerId, String timestamp, int durationSec, String status) {
            this.caller = caller;
            this.callee = callee;
            this.towerId = towerId;
            this.timestamp = timestamp;
            this.durationSec = durationSec;
            this.status = status;
        }

        public String getCaller() { return caller; }
        public String getCallee() { return callee; }
        public String getTowerId() { return towerId; }
        public String getTimestamp() { return timestamp; }
        public int getDurationSec() { return durationSec; }
        public String getStatus() { return status; }

        public String toJson() {
            return String.format(
                "{\"caller\":\"%s\",\"callee\":\"%s\",\"tower_id\":\"%s\",\"timestamp\":\"%s\",\"duration_sec\":%d,\"status\":\"%s\"}",
                escape(caller), escape(callee), escape(towerId), escape(timestamp), durationSec, escape(status)
            );
        }
    }

    public static class FinancialRecord {
        private final String sender;
        private final String receiver;
        private final double amount;
        private final String category;
        private final String merchant;
        private final String timestamp;

        public FinancialRecord(String sender, String receiver, double amount, String category, String merchant, String timestamp) {
            this.sender = sender;
            this.receiver = receiver;
            this.amount = amount;
            this.category = category;
            this.merchant = merchant;
            this.timestamp = timestamp;
        }

        public String getSender() { return sender; }
        public String getReceiver() { return receiver; }
        public double getAmount() { return amount; }
        public String getCategory() { return category; }
        public String getMerchant() { return merchant; }
        public String getTimestamp() { return timestamp; }

        public String toJson() {
            return String.format(
                "{\"sender\":\"%s\",\"receiver\":\"%s\",\"amount\":%.2f,\"category\":\"%s\",\"merchant\":\"%s\",\"timestamp\":\"%s\"}",
                escape(sender), escape(receiver), amount, escape(category), escape(merchant), escape(timestamp)
            );
        }
    }

    public static class FIRRecord {
        private final String firNumber;
        private final String policeStation;
        private final String incidentDate;
        private final String rawText;

        public FIRRecord(String firNumber, String policeStation, String incidentDate, String rawText) {
            this.firNumber = firNumber;
            this.policeStation = policeStation;
            this.incidentDate = incidentDate;
            this.rawText = rawText;
        }

        public String getFirNumber() { return firNumber; }
        public String getPoliceStation() { return policeStation; }
        public String getIncidentDate() { return incidentDate; }
        public String getRawText() { return rawText; }

        public String toJson() {
            return String.format(
                "{\"fir_number\":\"%s\",\"police_station\":\"%s\",\"incident_date\":\"%s\",\"raw_text\":\"%s\"}",
                escape(firNumber), escape(policeStation), escape(incidentDate), escape(rawText)
            );
        }
    }

    // --- Cryptographic SHA-256 Engine ---

    public static class FileHasher {
        public static String calculateSha256(File file) throws IOException, NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream fis = new BufferedInputStream(new FileInputStream(file))) {
                byte[] buffer = new byte[8192];
                int n = 0;
                while ((n = fis.read(buffer)) != -1) {
                    digest.update(buffer, 0, n);
                }
            }
            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }

        public static String calculateSha256String(String text) throws NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }
    }

    // --- Levenshtein Distance Implementation ---

    public static class Levenshtein {
        public static int distance(String s1, String s2) {
            if (s1 == null && s2 == null) return 0;
            if (s1 == null) return s2.length();
            if (s2 == null) return s1.length();

            String a = s1.trim().toLowerCase();
            String b = s2.trim().toLowerCase();

            int len0 = a.length() + 1;
            int len1 = b.length() + 1;

            int[] cost = new int[len0];
            int[] newcost = new int[len0];

            for (int i = 0; i < len0; i++) cost[i] = i;

            for (int j = 1; j < len1; j++) {
                newcost[0] = j;
                for (int i = 1; i < len0; i++) {
                    int match = (a.charAt(i - 1) == b.charAt(j - 1)) ? 0 : 1;
                    int costReplace = cost[i - 1] + match;
                    int costInsert = cost[i] + 1;
                    int costDelete = newcost[i - 1] + 1;
                    newcost[i] = Math.min(Math.min(costInsert, costDelete), costReplace);
                }
                int[] swap = cost; cost = newcost; newcost = swap;
            }
            return cost[len0 - 1];
        }

        public static boolean isMatch(String s1, String s2, int maxThreshold) {
            return distance(s1, s2) <= maxThreshold;
        }
    }

    // --- Bulk Streaming Parsers ---

    public static List<CDRRecord> parseCDRFile(File csvFile) throws IOException {
        List<CDRRecord> records = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(csvFile), StandardCharsets.UTF_8))) {
            String line = br.readLine(); // Header
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                String[] parts = parseCsvLine(line);
                if (parts.length >= 4) {
                    String caller = parts[0].trim();
                    String callee = parts[1].trim();
                    String towerId = parts.length > 2 ? parts[2].trim() : "UNKNOWN";
                    String timestamp = parts.length > 3 ? parts[3].trim() : "";
                    int duration = parts.length > 4 ? safeParseInt(parts[4].trim(), 60) : 60;
                    String status = parts.length > 5 ? parts[5].trim() : "Active";
                    records.add(new CDRRecord(caller, callee, towerId, timestamp, duration, status));
                }
            }
        }
        return records;
    }

    public static List<FinancialRecord> parseFinancialFile(File csvFile) throws IOException {
        List<FinancialRecord> records = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(csvFile), StandardCharsets.UTF_8))) {
            String line = br.readLine(); // Header
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                String[] parts = parseCsvLine(line);
                if (parts.length >= 3) {
                    String sender = parts[0].trim();
                    String receiver = parts[1].trim();
                    double amount = safeParseDouble(parts[2].trim(), 0.0);
                    String category = parts.length > 3 ? parts[3].trim() : "TRANSFER";
                    String merchant = parts.length > 4 ? parts[4].trim() : "General";
                    String timestamp = parts.length > 5 ? parts[5].trim() : "";
                    records.add(new FinancialRecord(sender, receiver, amount, category, merchant, timestamp));
                }
            }
        }
        return records;
    }

    // --- Helper Utilities ---

    private static String[] parseCsvLine(String line) {
        List<String> tokens = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '\"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                tokens.add(sb.toString());
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }
        tokens.add(sb.toString());
        return tokens.toArray(new String[0]);
    }

    private static int safeParseInt(String val, int def) {
        try { return Integer.parseInt(val.replaceAll("[^0-9\\-]", "")); }
        catch (Exception e) { return def; }
    }

    private static double safeParseDouble(String val, double def) {
        try { return Double.parseDouble(val.replaceAll("[^0-9.\\-]", "")); }
        catch (Exception e) { return def; }
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ");
    }

    // --- Main CLI Entrypoint ---

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("{\"error\":\"Insufficient arguments. Usage: BulkDataProcessor <command> <arg>\"}");
            return;
        }

        String command = args[0];
        String target = args[1];

        try {
            switch (command) {
                case "hash":
                    File f = new File(target);
                    if (!f.exists()) {
                        System.out.println("{\"error\":\"File not found\"}");
                    } else {
                        String hash = FileHasher.calculateSha256(f);
                        System.out.printf("{\"file\":\"%s\",\"sha256\":\"%s\",\"size_bytes\":%d}%n", escape(target), hash, f.length());
                    }
                    break;

                case "levenshtein":
                    if (args.length < 3) {
                        System.out.println("{\"error\":\"Requires two strings\"}");
                    } else {
                        int dist = Levenshtein.distance(args[1], args[2]);
                        System.out.printf("{\"str1\":\"%s\",\"str2\":\"%s\",\"distance\":%d,\"match_le2\":%b}%n",
                            escape(args[1]), escape(args[2]), dist, dist <= 2);
                    }
                    break;

                case "parse-cdr":
                    List<CDRRecord> cdrs = parseCDRFile(new File(target));
                    System.out.print("{\"count\":" + cdrs.size() + ",\"records\":[");
                    for (int i = 0; i < cdrs.size(); i++) {
                        System.out.print(cdrs.get(i).toJson());
                        if (i < cdrs.size() - 1) System.out.print(",");
                    }
                    System.out.println("]}");
                    break;

                case "parse-financial":
                    List<FinancialRecord> fins = parseFinancialFile(new File(target));
                    System.out.print("{\"count\":" + fins.size() + ",\"records\":[");
                    for (int i = 0; i < fins.size(); i++) {
                        System.out.print(fins.get(i).toJson());
                        if (i < fins.size() - 1) System.out.print(",");
                    }
                    System.out.println("]}");
                    break;

                default:
                    System.out.println("{\"error\":\"Unknown command: " + escape(command) + "\"}");
            }
        } catch (Exception e) {
            System.out.printf("{\"error\":\"%s\"}%n", escape(e.getMessage()));
        }
    }
}
