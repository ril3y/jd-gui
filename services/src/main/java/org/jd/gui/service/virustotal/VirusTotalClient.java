/*
 * Copyright (c) 2008-2019 Emmanuel Dupuy.
 * This project is distributed under the GPLv3 license.
 * This is a Copyleft license that gives the user the right to use,
 * copy and modify the code freely for non-commercial purposes.
 */

package org.jd.gui.service.virustotal;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VirusTotalClient {
    private static final String VT_API_BASE_URL = "https://www.virustotal.com/api/v3";
    private static final String VT_FILES_ENDPOINT = "/files/";
    private static final int TIMEOUT_MS = 30000; // 30 seconds

    // Regex patterns for extracting key information from JSON response
    private static final Pattern STATS_PATTERN = Pattern.compile("\"stats\"\\s*:\\s*\\{([^}]+)\\}");
    private static final Pattern MALICIOUS_PATTERN = Pattern.compile("\"malicious\"\\s*:\\s*(\\d+)");
    private static final Pattern SUSPICIOUS_PATTERN = Pattern.compile("\"suspicious\"\\s*:\\s*(\\d+)");
    private static final Pattern UNDETECTED_PATTERN = Pattern.compile("\"undetected\"\\s*:\\s*(\\d+)");
    private static final Pattern HARMLESS_PATTERN = Pattern.compile("\"harmless\"\\s*:\\s*(\\d+)");
    private static final Pattern REPUTATION_PATTERN = Pattern.compile("\"reputation\"\\s*:\\s*(-?\\d+)");

    public static class VirusTotalResponse {
        private final boolean found;
        private final int malicious;
        private final int suspicious;
        private final int undetected;
        private final int harmless;
        private final int reputation;
        private final String rawJson;
        private final String errorMessage;

        public VirusTotalResponse(boolean found, int malicious, int suspicious, int undetected, int harmless, int reputation, String rawJson) {
            this.found = found;
            this.malicious = malicious;
            this.suspicious = suspicious;
            this.undetected = undetected;
            this.harmless = harmless;
            this.reputation = reputation;
            this.rawJson = rawJson;
            this.errorMessage = null;
        }

        public VirusTotalResponse(String errorMessage) {
            this.found = false;
            this.malicious = 0;
            this.suspicious = 0;
            this.undetected = 0;
            this.harmless = 0;
            this.reputation = 0;
            this.rawJson = null;
            this.errorMessage = errorMessage;
        }

        public boolean isFound() { return found; }
        public int getMalicious() { return malicious; }
        public int getSuspicious() { return suspicious; }
        public int getUndetected() { return undetected; }
        public int getHarmless() { return harmless; }
        public int getReputation() { return reputation; }
        public String getRawJson() { return rawJson; }
        public String getErrorMessage() { return errorMessage; }
        public boolean hasError() { return errorMessage != null; }

        public int getTotalScans() {
            return malicious + suspicious + undetected + harmless;
        }

        public boolean isMalicious() {
            return malicious > 0 || suspicious > 0;
        }
    }

    public VirusTotalResponse checkHash(String hash, String apiKey) {
        if (hash == null || hash.trim().isEmpty()) {
            return new VirusTotalResponse("Hash cannot be empty");
        }

        if (apiKey == null || apiKey.trim().isEmpty()) {
            return new VirusTotalResponse("API key cannot be empty");
        }

        HttpsURLConnection connection = null;
        try {
            // Build URL
            String urlString = VT_API_BASE_URL + VT_FILES_ENDPOINT + hash.trim().toLowerCase();
            URL url = new URL(urlString);

            // Create connection
            connection = (HttpsURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setRequestProperty("X-Apikey", apiKey.trim());
            connection.setRequestProperty("User-Agent", "JD-GUI");
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);

            // Get response
            int responseCode = connection.getResponseCode();

            if (responseCode == 200) {
                // Success - parse response
                String response = readResponse(connection);
                return parseResponse(response);

            } else if (responseCode == 404) {
                // Hash not found in VirusTotal database
                return new VirusTotalResponse("Hash not found in VirusTotal database");

            } else if (responseCode == 401) {
                return new VirusTotalResponse("Invalid API key");

            } else if (responseCode == 429) {
                return new VirusTotalResponse("Rate limit exceeded. Please wait before making another request.");

            } else {
                String errorBody = readErrorResponse(connection);
                return new VirusTotalResponse("HTTP " + responseCode + ": " + errorBody);
            }

        } catch (IOException e) {
            return new VirusTotalResponse("Network error: " + e.getMessage());
        } catch (Exception e) {
            return new VirusTotalResponse("Unexpected error: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private String readResponse(HttpURLConnection connection) throws IOException {
        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line).append("\n");
            }
        }
        return response.toString();
    }

    private String readErrorResponse(HttpURLConnection connection) {
        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line).append(" ");
            }
        } catch (Exception e) {
            return "Error reading response";
        }
        return response.toString().trim();
    }

    private VirusTotalResponse parseResponse(String json) {
        try {
            // Extract stats section
            Matcher statsMatcher = STATS_PATTERN.matcher(json);
            if (!statsMatcher.find()) {
                return new VirusTotalResponse("Unable to parse VirusTotal response");
            }

            String statsSection = statsMatcher.group(1);

            // Extract individual counts
            int malicious = extractInt(MALICIOUS_PATTERN, statsSection, 0);
            int suspicious = extractInt(SUSPICIOUS_PATTERN, statsSection, 0);
            int undetected = extractInt(UNDETECTED_PATTERN, statsSection, 0);
            int harmless = extractInt(HARMLESS_PATTERN, statsSection, 0);

            // Extract reputation (optional)
            int reputation = extractInt(REPUTATION_PATTERN, json, 0);

            return new VirusTotalResponse(true, malicious, suspicious, undetected, harmless, reputation, json);

        } catch (Exception e) {
            return new VirusTotalResponse("Error parsing response: " + e.getMessage());
        }
    }

    private int extractInt(Pattern pattern, String text, int defaultValue) {
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            try {
                return Integer.parseInt(matcher.group(1));
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }
        return defaultValue;
    }
}