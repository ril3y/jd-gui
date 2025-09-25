/*
 * Copyright (c) 2008-2019 Emmanuel Dupuy.
 * This project is distributed under the GPLv3 license.
 * This is a Copyleft license that gives the user the right to use,
 * copy and modify the code freely for non-commercial purposes.
 */

package org.jd.gui.service.preferencespanel;

import org.jd.gui.spi.PreferencesPanel;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Map;

public class VirusTotalPreferencesProvider extends JPanel implements PreferencesPanel, DocumentListener {
    protected static final String API_KEY_KEY = "VirusTotal.apiKey";
    protected static final String RATE_LIMIT_KEY = "VirusTotal.rateLimitSeconds";
    protected static final String VT_API_URL = "https://www.virustotal.com/gui/my-apikey";

    protected PreferencesPanel.PreferencesPanelChangeListener listener = null;
    protected JTextField apiKeyTextField;
    protected JTextField rateLimitTextField;
    protected Color errorBackgroundColor = Color.RED;
    protected Color defaultBackgroundColor;

    public VirusTotalPreferencesProvider() {
        super(new BorderLayout());

        // Create main panel
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        // API Key label and field
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(5, 5, 5, 5);
        mainPanel.add(new JLabel("API Key:"), gbc);

        gbc.gridx = 1; gbc.gridy = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        apiKeyTextField = new JTextField(40);
        apiKeyTextField.getDocument().addDocumentListener(this);
        mainPanel.add(apiKeyTextField, gbc);

        // Help button
        gbc.gridx = 2; gbc.gridy = 0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        JButton helpButton = new JButton("Get API Key");
        helpButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    Desktop.getDesktop().browse(java.net.URI.create(VT_API_URL));
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(
                        VirusTotalPreferencesProvider.this,
                        "Please visit: " + VT_API_URL + "\nto obtain your free VirusTotal API key.",
                        "Get API Key",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                }
            }
        });
        mainPanel.add(helpButton, gbc);

        // Rate limit label and field
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.insets = new Insets(5, 5, 5, 5);
        mainPanel.add(new JLabel("Rate Limit (seconds):"), gbc);

        gbc.gridx = 1; gbc.gridy = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        rateLimitTextField = new JTextField("1", 10);
        rateLimitTextField.getDocument().addDocumentListener(this);
        mainPanel.add(rateLimitTextField, gbc);

        gbc.gridx = 2; gbc.gridy = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        JLabel rateLimitHelpLabel = new JLabel("(1 for free API, 0.25 for paid)");
        rateLimitHelpLabel.setFont(rateLimitHelpLabel.getFont().deriveFont(Font.ITALIC, 10f));
        mainPanel.add(rateLimitHelpLabel, gbc);

        // Instructions
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 5, 5, 5);
        JTextArea instructions = new JTextArea(
            "Enter your VirusTotal API key to enable hash lookup functionality.\n" +
            "A free API key allows 4 requests per minute.\n" +
            "Leave empty to disable VirusTotal integration."
        );
        instructions.setEditable(false);
        instructions.setOpaque(false);
        instructions.setFont(instructions.getFont().deriveFont(Font.ITALIC));
        instructions.setBorder(null);
        mainPanel.add(instructions, gbc);

        add(mainPanel, BorderLayout.NORTH);
        defaultBackgroundColor = apiKeyTextField.getBackground();
    }

    // --- PreferencesPanel --- //
    @Override public String getPreferencesGroupTitle() { return "VirusTotal"; }
    @Override public String getPreferencesPanelTitle() { return "API Configuration"; }
    @Override public JComponent getPanel() { return this; }

    @Override public void init(Color errorBackgroundColor) {
        this.errorBackgroundColor = errorBackgroundColor;
    }

    @Override public boolean isActivated() { return true; }

    @Override
    public void loadPreferences(Map<String, String> preferences) {
        String apiKey = preferences.get(API_KEY_KEY);

        // Fallback to environment variable if not in preferences (secure approach)
        if (apiKey == null || apiKey.trim().isEmpty()) {
            apiKey = System.getenv("VIRUSTOTAL_API_KEY");
            if (apiKey == null) {
                apiKey = "";
            }
        }
        apiKeyTextField.setText(apiKey);
        apiKeyTextField.setCaretPosition(apiKeyTextField.getText().length());

        String rateLimit = preferences.get(RATE_LIMIT_KEY);
        if (rateLimit == null) {
            // Fallback to environment variable
            rateLimit = System.getenv("VIRUSTOTAL_RATE_LIMIT");
            if (rateLimit == null) {
                rateLimit = "1"; // Default to 1 second
            }
        }
        rateLimitTextField.setText(rateLimit);
    }

    @Override
    public void savePreferences(Map<String, String> preferences) {
        String apiKey = apiKeyTextField.getText().trim();
        if (!apiKey.isEmpty()) {
            preferences.put(API_KEY_KEY, apiKey);
        } else {
            preferences.remove(API_KEY_KEY);
        }

        String rateLimit = rateLimitTextField.getText().trim();
        if (!rateLimit.isEmpty()) {
            preferences.put(RATE_LIMIT_KEY, rateLimit);
        } else {
            preferences.put(RATE_LIMIT_KEY, "1"); // Default fallback
        }
    }

    @Override
    public boolean arePreferencesValid() {
        String apiKey = apiKeyTextField.getText().trim();
        // Empty is valid (disables functionality)
        if (apiKey.isEmpty()) {
            return true;
        }
        // Basic validation: VirusTotal API keys are typically 64-character hex strings
        boolean apiKeyValid = apiKey.matches("[a-fA-F0-9]{64}");

        // Validate rate limit
        String rateLimit = rateLimitTextField.getText().trim();
        boolean rateLimitValid = true;
        try {
            double rate = Double.parseDouble(rateLimit);
            rateLimitValid = rate > 0 && rate <= 60; // Between 0 and 60 seconds
        } catch (NumberFormatException e) {
            rateLimitValid = false;
        }

        return apiKeyValid && rateLimitValid;
    }

    @Override
    public void addPreferencesChangeListener(PreferencesPanel.PreferencesPanelChangeListener listener) {
        this.listener = listener;
    }

    // --- DocumentListener --- //
    @Override public void insertUpdate(DocumentEvent e) { onTextChange(); }
    @Override public void removeUpdate(DocumentEvent e) { onTextChange(); }
    @Override public void changedUpdate(DocumentEvent e) { onTextChange(); }

    public void onTextChange() {
        apiKeyTextField.setBackground(arePreferencesValid() ? defaultBackgroundColor : errorBackgroundColor);

        if (listener != null) {
            listener.preferencesPanelChanged(this);
        }
    }
}