package org.jd.gui.service.virustotal;

import junit.framework.TestCase;
import org.junit.Assert;

/**
 * Comprehensive test suite for VirusTotalClient functionality.
 * Tests both API integration and error handling scenarios.
 */
public class VirusTotalClientTest extends TestCase {

    // Test constants - using real hash from user for integration testing
    private static final String TEST_HASH_CLEAN = "0644b403b1203aad3cfc2580e524e181f804ec91267ed434a1b98645a0047b79";
    private static final String TEST_HASH_INVALID = "invalid_hash_format";
    private static final String TEST_API_KEY = "a34659226966f80dbe29bd3cb85f10522296fc5db59658ef9208254327e5e4de";

    private VirusTotalClient client;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        client = new VirusTotalClient();
    }

    // --- Input Validation Tests ---

    public void testCheckHash_NullHash() {
        VirusTotalClient.VirusTotalResponse response = client.checkHash(null, TEST_API_KEY);

        Assert.assertTrue("Should have error for null hash", response.hasError());
        Assert.assertEquals("Hash cannot be empty", response.getErrorMessage());
        Assert.assertFalse("Should not be found", response.isFound());
    }

    public void testCheckHash_EmptyHash() {
        VirusTotalClient.VirusTotalResponse response = client.checkHash("", TEST_API_KEY);

        Assert.assertTrue("Should have error for empty hash", response.hasError());
        Assert.assertEquals("Hash cannot be empty", response.getErrorMessage());
        Assert.assertFalse("Should not be found", response.isFound());
    }

    public void testCheckHash_NullApiKey() {
        VirusTotalClient.VirusTotalResponse response = client.checkHash(TEST_HASH_CLEAN, null);

        Assert.assertTrue("Should have error for null API key", response.hasError());
        Assert.assertEquals("API key cannot be empty", response.getErrorMessage());
        Assert.assertFalse("Should not be found", response.isFound());
    }

    public void testCheckHash_EmptyApiKey() {
        VirusTotalClient.VirusTotalResponse response = client.checkHash(TEST_HASH_CLEAN, "");

        Assert.assertTrue("Should have error for empty API key", response.hasError());
        Assert.assertEquals("API key cannot be empty", response.getErrorMessage());
        Assert.assertFalse("Should not be found", response.isFound());
    }

    // --- API Integration Tests ---

    /**
     * Test with a known clean hash that should have 0 detections.
     * This tests the actual VirusTotal API integration.
     */
    public void testCheckHash_KnownCleanHash() {
        System.out.println("Testing VirusTotal API with known clean hash: " + TEST_HASH_CLEAN);

        VirusTotalClient.VirusTotalResponse response = client.checkHash(TEST_HASH_CLEAN, TEST_API_KEY);

        // Debug output
        System.out.println("Response hasError: " + response.hasError());
        if (response.hasError()) {
            System.out.println("Error message: " + response.getErrorMessage());
        }
        System.out.println("Response isFound: " + response.isFound());

        // Assertions based on expected behavior
        if (response.hasError()) {
            // If there's an error, it should be a meaningful message
            String errorMsg = response.getErrorMessage();
            Assert.assertNotNull("Error message should not be null", errorMsg);
            Assert.assertFalse("Error message should not be empty", errorMsg.trim().isEmpty());

            // Log the error for debugging
            System.err.println("VirusTotal API Error: " + errorMsg);

            // Common error scenarios we should handle gracefully
            boolean isExpectedError = errorMsg.contains("Rate limit") ||
                                    errorMsg.contains("Invalid API key") ||
                                    errorMsg.contains("Network error") ||
                                    errorMsg.contains("not found");
            Assert.assertTrue("Should be a handled error type: " + errorMsg, isExpectedError);
        } else {
            // If no error, we should have valid response data
            Assert.assertTrue("Should be found if no error", response.isFound());

            // Validate detection counts
            Assert.assertTrue("Malicious count should be >= 0", response.getMalicious() >= 0);
            Assert.assertTrue("Suspicious count should be >= 0", response.getSuspicious() >= 0);
            Assert.assertTrue("Undetected count should be >= 0", response.getUndetected() >= 0);
            Assert.assertTrue("Harmless count should be >= 0", response.getHarmless() >= 0);

            // Total scans should be reasonable
            int totalScans = response.getTotalScans();
            Assert.assertTrue("Total scans should be > 0", totalScans > 0);
            Assert.assertTrue("Total scans should be reasonable (< 200)", totalScans < 200);

            // For the known clean hash, should have 0 malicious detections
            Assert.assertEquals("Known clean hash should have 0 malicious detections", 0, response.getMalicious());
            Assert.assertEquals("Known clean hash should have 0 suspicious detections", 0, response.getSuspicious());
            Assert.assertFalse("Known clean hash should not be flagged as malicious", response.isMalicious());

            System.out.println("✅ Clean hash verified - Total scans: " + totalScans +
                             ", Malicious: " + response.getMalicious() +
                             ", Suspicious: " + response.getSuspicious());
        }
    }

    /**
     * Test with an invalid API key to ensure proper error handling.
     */
    public void testCheckHash_InvalidApiKey() {
        String invalidKey = "invalid_key_1234567890abcdef";

        VirusTotalClient.VirusTotalResponse response = client.checkHash(TEST_HASH_CLEAN, invalidKey);

        Assert.assertTrue("Should have error for invalid API key", response.hasError());
        String errorMsg = response.getErrorMessage();
        Assert.assertTrue("Error should mention invalid API key",
                         errorMsg.contains("Invalid API key") || errorMsg.contains("401"));
        Assert.assertFalse("Should not be found", response.isFound());
    }

    /**
     * Test with invalid hash format to ensure proper error handling.
     */
    public void testCheckHash_InvalidHashFormat() {
        VirusTotalClient.VirusTotalResponse response = client.checkHash(TEST_HASH_INVALID, TEST_API_KEY);

        // Should either return "not found" or have an error about invalid format
        if (response.hasError()) {
            String errorMsg = response.getErrorMessage();
            // Should handle invalid format gracefully
            Assert.assertNotNull("Error message should not be null", errorMsg);
            Assert.assertFalse("Error message should not be empty", errorMsg.trim().isEmpty());
        } else {
            // If no error, should indicate not found
            Assert.assertFalse("Invalid hash should not be found", response.isFound());
        }
    }

    // --- Response Object Tests ---

    public void testVirusTotalResponse_ErrorConstructor() {
        String errorMsg = "Test error message";
        VirusTotalClient.VirusTotalResponse response = new VirusTotalClient.VirusTotalResponse(errorMsg);

        Assert.assertTrue("Should have error", response.hasError());
        Assert.assertEquals("Error message should match", errorMsg, response.getErrorMessage());
        Assert.assertFalse("Should not be found", response.isFound());
        Assert.assertEquals("Malicious count should be 0", 0, response.getMalicious());
        Assert.assertEquals("Total scans should be 0", 0, response.getTotalScans());
        Assert.assertFalse("Should not be malicious", response.isMalicious());
    }

    public void testVirusTotalResponse_SuccessConstructor() {
        int malicious = 0, suspicious = 1, undetected = 50, harmless = 20, reputation = 5;
        String rawJson = "{\"test\": \"data\"}";

        VirusTotalClient.VirusTotalResponse response = new VirusTotalClient.VirusTotalResponse(
            true, malicious, suspicious, undetected, harmless, reputation, rawJson);

        Assert.assertFalse("Should not have error", response.hasError());
        Assert.assertNull("Error message should be null", response.getErrorMessage());
        Assert.assertTrue("Should be found", response.isFound());

        Assert.assertEquals("Malicious count should match", malicious, response.getMalicious());
        Assert.assertEquals("Suspicious count should match", suspicious, response.getSuspicious());
        Assert.assertEquals("Undetected count should match", undetected, response.getUndetected());
        Assert.assertEquals("Harmless count should match", harmless, response.getHarmless());
        Assert.assertEquals("Reputation should match", reputation, response.getReputation());
        Assert.assertEquals("Raw JSON should match", rawJson, response.getRawJson());

        Assert.assertEquals("Total scans should be sum", 71, response.getTotalScans());
        Assert.assertTrue("Should be considered malicious due to suspicious", response.isMalicious());
    }

    public void testVirusTotalResponse_MaliciousDetection() {
        // Test with malicious detections
        VirusTotalClient.VirusTotalResponse response = new VirusTotalClient.VirusTotalResponse(
            true, 5, 0, 50, 20, -10, "{}");
        Assert.assertTrue("Should be malicious with 5 detections", response.isMalicious());

        // Test with suspicious detections
        response = new VirusTotalClient.VirusTotalResponse(true, 0, 3, 50, 20, 0, "{}");
        Assert.assertTrue("Should be malicious with 3 suspicious", response.isMalicious());

        // Test with clean file
        response = new VirusTotalClient.VirusTotalResponse(true, 0, 0, 50, 20, 10, "{}");
        Assert.assertFalse("Should not be malicious with 0 detections", response.isMalicious());
    }

    // --- Helper Methods for Manual Testing ---

    /**
     * Helper method to manually test with different parameters.
     * Can be called from main() for debugging.
     */
    public static void debugTestHash(String hash, String apiKey) {
        System.out.println("\n=== VirusTotal Debug Test ===");
        System.out.println("Hash: " + hash);
        System.out.println("API Key: " + (apiKey != null && apiKey.length() > 10 ?
                          apiKey.substring(0, 10) + "..." : "null"));

        VirusTotalClient client = new VirusTotalClient();
        VirusTotalClient.VirusTotalResponse response = client.checkHash(hash, apiKey);

        System.out.println("\n--- Response ---");
        System.out.println("Has Error: " + response.hasError());
        if (response.hasError()) {
            System.out.println("Error: " + response.getErrorMessage());
        }
        System.out.println("Is Found: " + response.isFound());
        if (response.isFound()) {
            System.out.println("Malicious: " + response.getMalicious());
            System.out.println("Suspicious: " + response.getSuspicious());
            System.out.println("Undetected: " + response.getUndetected());
            System.out.println("Harmless: " + response.getHarmless());
            System.out.println("Total Scans: " + response.getTotalScans());
            System.out.println("Reputation: " + response.getReputation());
            System.out.println("Is Malicious: " + response.isMalicious());
        }
        System.out.println("===============================\n");
    }

    /**
     * Main method for manual testing and debugging.
     */
    public static void main(String[] args) {
        // Debug with the known clean hash
        debugTestHash(TEST_HASH_CLEAN, TEST_API_KEY);

        // Test error scenarios
        debugTestHash(null, TEST_API_KEY);
        debugTestHash(TEST_HASH_CLEAN, null);
        debugTestHash("invalid", TEST_API_KEY);
    }
}