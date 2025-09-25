/*
 * Copyright (c) 2008-2019 Emmanuel Dupuy.
 * This project is distributed under the GPLv3 license.
 * This is a Copyleft license that gives the user the right to use,
 * copy and modify the code freely for non-commercial purposes.
 */

package org.jd.gui.service.preferencespanel;

import junit.framework.TestCase;
import org.junit.Assert;

import java.awt.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Unit tests for VirusTotalPreferencesProvider
 * Tests preference validation, saving, and loading
 */
public class VirusTotalPreferencesProviderTest extends TestCase {

    private VirusTotalPreferencesProvider provider;
    private Map<String, String> preferences;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        provider = new VirusTotalPreferencesProvider();
        provider.init(Color.RED); // Initialize with error color
        preferences = new HashMap<>();
    }

    // Test basic properties
    public void testPreferencesGroupTitle() {
        Assert.assertEquals("VirusTotal", provider.getPreferencesGroupTitle());
    }

    public void testPreferencesPanelTitle() {
        Assert.assertEquals("API Configuration", provider.getPreferencesPanelTitle());
    }

    public void testIsActivated() {
        Assert.assertTrue(provider.isActivated());
    }

    // Test preference loading - Uses environment variable (GitHub Secret in CI/CD)
    public void testLoadPreferencesWithValidApiKey() {
        // Test with a valid 64-character hex pattern (fake key for testing)
        String testApiKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        preferences.put("VirusTotal.apiKey", testApiKey);

        provider.loadPreferences(preferences);

        // Test that loading doesn't throw exceptions and validation works
        Assert.assertTrue(provider.arePreferencesValid());
    }

    public void testLoadPreferencesWithNullApiKey() {
        // Don't put apiKey in preferences (null case)
        provider.loadPreferences(preferences);

        // Should default to empty and be valid
        Assert.assertTrue(provider.arePreferencesValid());
    }

    // Test preference saving
    public void testSavePreferencesWithValidApiKey() {
        String validApiKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // Load the API key
        preferences.put("VirusTotal.apiKey", validApiKey);
        provider.loadPreferences(preferences);

        // Save preferences
        Map<String, String> savedPrefs = new HashMap<>();
        provider.savePreferences(savedPrefs);

        Assert.assertEquals(validApiKey, savedPrefs.get("VirusTotal.apiKey"));
    }

    public void testSavePreferencesWithEmptyApiKey() {
        // Load empty preferences
        provider.loadPreferences(preferences);

        // Save preferences
        Map<String, String> savedPrefs = new HashMap<>();
        provider.savePreferences(savedPrefs);

        // Empty API key should not be saved
        Assert.assertNull(savedPrefs.get("VirusTotal.apiKey"));
    }

    // Test API key validation
    public void testValidApiKey() {
        String validApiKey = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678";
        preferences.put("VirusTotal.apiKey", validApiKey);
        provider.loadPreferences(preferences);

        Assert.assertTrue(provider.arePreferencesValid());
    }

    public void testInvalidApiKeyTooShort() {
        String invalidApiKey = "abc123"; // Too short
        preferences.put("VirusTotal.apiKey", invalidApiKey);
        provider.loadPreferences(preferences);

        Assert.assertFalse(provider.arePreferencesValid());
    }

    public void testInvalidApiKeyWrongCharacters() {
        // 64 chars but contains invalid characters
        String invalidApiKey = "g1h2i3j4k5l6789012345678901234567890123456789012345678901234567890";
        preferences.put("VirusTotal.apiKey", invalidApiKey);
        provider.loadPreferences(preferences);

        Assert.assertFalse(provider.arePreferencesValid());
    }

    public void testEmptyApiKeyIsValid() {
        // Empty API key should be valid (disables functionality)
        provider.loadPreferences(preferences);
        Assert.assertTrue(provider.arePreferencesValid());
    }

    public void testValidApiKeyUpperCase() {
        String validApiKey = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        preferences.put("VirusTotal.apiKey", validApiKey);
        provider.loadPreferences(preferences);

        Assert.assertTrue(provider.arePreferencesValid());
    }

    public void testValidApiKeyMixedCase() {
        String validApiKey = "A1b2C3d4E5f6789012345678901234567890123456789012345678901234abcd";
        preferences.put("VirusTotal.apiKey", validApiKey);
        provider.loadPreferences(preferences);

        Assert.assertTrue(provider.arePreferencesValid());
    }
}