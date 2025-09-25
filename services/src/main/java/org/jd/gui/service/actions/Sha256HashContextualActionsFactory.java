/*
 * Copyright (c) 2008-2019 Emmanuel Dupuy.
 * This project is distributed under the GPLv3 license.
 * This is a Copyleft license that gives the user the right to use,
 * copy and modify the code freely for non-commercial purposes.
 */

package org.jd.gui.service.actions;

import org.jd.gui.api.API;
import org.jd.gui.api.model.Container;
import org.jd.gui.service.virustotal.VirusTotalClient;
import org.jd.gui.spi.ContextualActionsFactory;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

public class Sha256HashContextualActionsFactory implements ContextualActionsFactory {

    public Collection<Action> make(API api, Container.Entry entry, String fragment) {
        // Only show for class files
        if (entry != null && entry.getPath().endsWith(".class")) {
            Collection<Action> actions = new ArrayList<Action>();

            // Always add the basic SHA256 generation
            actions.add(new GenerateSha256Action(api, entry, fragment));

            // Add VirusTotal lookup if API key is configured
            String apiKey = api.getPreferences().get("VirusTotal.apiKey");
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                actions.add(new CheckVirusTotalAction(api, entry, fragment));
            }

            return actions;
        }
        return Collections.emptyList();
    }

    public static class GenerateSha256Action extends AbstractAction {
        protected static final ImageIcon ICON = new ImageIcon(GenerateSha256Action.class.getClassLoader().getResource("org/jd/gui/images/cpyqual_menu.png"));

        protected API api;
        protected Container.Entry entry;
        protected String fragment;

        public GenerateSha256Action(API api, Container.Entry entry, String fragment) {
            this.api = api;
            this.entry = entry;
            this.fragment = fragment;

            putValue(GROUP_NAME, "Tools > Hash");
            putValue(NAME, "Generate SHA256 Hash");
            putValue(SMALL_ICON, ICON);
        }

        public void actionPerformed(ActionEvent e) {
            try {
                String hash = generateSha256Hash(entry);

                // Copy to clipboard
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(hash), null);

                // Show dialog with hash
                String filename = entry.getPath().substring(entry.getPath().lastIndexOf('/') + 1);
                JOptionPane.showMessageDialog(
                    null,
                    "SHA256 hash for " + filename + ":\n\n" + hash + "\n\n(Hash copied to clipboard)",
                    "SHA256 Hash",
                    JOptionPane.INFORMATION_MESSAGE
                );

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(
                    null,
                    "Error generating SHA256 hash: " + ex.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE
                );
            }
        }

        private String generateSha256Hash(Container.Entry entry) throws IOException, NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            try (InputStream is = entry.getInputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;

                while ((bytesRead = is.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();

            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }

            return sb.toString();
        }
    }

    public static class CheckVirusTotalAction extends AbstractAction {
        protected static final ImageIcon ICON = new ImageIcon(CheckVirusTotalAction.class.getClassLoader().getResource("org/jd/gui/images/cpyqual_menu.png"));

        protected API api;
        protected Container.Entry entry;
        protected String fragment;

        public CheckVirusTotalAction(API api, Container.Entry entry, String fragment) {
            this.api = api;
            this.entry = entry;
            this.fragment = fragment;

            putValue(GROUP_NAME, "Tools > Hash");
            putValue(NAME, "Check with VirusTotal");
            putValue(SMALL_ICON, ICON);
        }

        public void actionPerformed(ActionEvent e) {
            // Show progress dialog
            JDialog progressDialog = createProgressDialog();
            progressDialog.setVisible(true);

            // Perform lookup in background thread
            SwingWorker<VirusTotalClient.VirusTotalResponse, Void> worker = new SwingWorker<VirusTotalClient.VirusTotalResponse, Void>() {
                @Override
                protected VirusTotalClient.VirusTotalResponse doInBackground() throws Exception {
                    // Generate hash
                    String hash = generateSha256Hash(entry);

                    // Get API key from preferences
                    String apiKey = api.getPreferences().get("VirusTotal.apiKey");

                    // Check with VirusTotal
                    VirusTotalClient client = new VirusTotalClient();
                    return client.checkHash(hash, apiKey);
                }

                @Override
                protected void done() {
                    progressDialog.dispose();

                    try {
                        VirusTotalClient.VirusTotalResponse response = get();
                        showVirusTotalResults(response);
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(
                            null,
                            "Error checking with VirusTotal: " + ex.getMessage(),
                            "VirusTotal Error",
                            JOptionPane.ERROR_MESSAGE
                        );
                    }
                }
            };

            worker.execute();
        }

        private JDialog createProgressDialog() {
            JDialog dialog = new JDialog((Frame) null, "VirusTotal Lookup", true);
            dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);

            JPanel panel = new JPanel(new BorderLayout(10, 10));
            panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

            JLabel label = new JLabel("Checking with VirusTotal...");
            label.setHorizontalAlignment(JLabel.CENTER);
            panel.add(label, BorderLayout.CENTER);

            JProgressBar progressBar = new JProgressBar();
            progressBar.setIndeterminate(true);
            panel.add(progressBar, BorderLayout.SOUTH);

            dialog.setContentPane(panel);
            dialog.pack();
            dialog.setLocationRelativeTo(null);

            return dialog;
        }

        private void showVirusTotalResults(VirusTotalClient.VirusTotalResponse response) {
            if (response.hasError()) {
                JOptionPane.showMessageDialog(
                    null,
                    "VirusTotal Error: " + response.getErrorMessage(),
                    "VirusTotal Error",
                    JOptionPane.ERROR_MESSAGE
                );
                return;
            }

            if (!response.isFound()) {
                JOptionPane.showMessageDialog(
                    null,
                    "This file hash was not found in the VirusTotal database.\n\nThis could mean:\n" +
                    "• The file has never been uploaded to VirusTotal\n" +
                    "• The file is very new or uncommon\n" +
                    "• The file is legitimate and clean",
                    "Hash Not Found",
                    JOptionPane.INFORMATION_MESSAGE
                );
                return;
            }

            // Format results
            StringBuilder results = new StringBuilder();
            String filename = entry.getPath().substring(entry.getPath().lastIndexOf('/') + 1);

            results.append("VirusTotal Results for ").append(filename).append(":\n\n");

            // Detection summary
            results.append("Detection Summary:\n");
            results.append("• Malicious: ").append(response.getMalicious()).append("\n");
            results.append("• Suspicious: ").append(response.getSuspicious()).append("\n");
            results.append("• Undetected: ").append(response.getUndetected()).append("\n");
            results.append("• Harmless: ").append(response.getHarmless()).append("\n");
            results.append("• Total scans: ").append(response.getTotalScans()).append("\n\n");

            // Reputation score
            if (response.getReputation() != 0) {
                results.append("Reputation: ").append(response.getReputation()).append("\n\n");
            }

            // Overall assessment
            if (response.isMalicious()) {
                results.append("⚠️ WARNING: This file has been flagged as malicious or suspicious by one or more antivirus engines!");
            } else {
                results.append("✅ This file appears to be clean based on current scans.");
            }

            // Determine message type and title
            int messageType = response.isMalicious() ? JOptionPane.WARNING_MESSAGE : JOptionPane.INFORMATION_MESSAGE;
            String title = response.isMalicious() ? "⚠️ Malicious File Detected" : "✅ VirusTotal Results";

            JOptionPane.showMessageDialog(
                null,
                results.toString(),
                title,
                messageType
            );
        }

        private String generateSha256Hash(Container.Entry entry) throws IOException, NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            try (InputStream is = entry.getInputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;

                while ((bytesRead = is.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();

            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }

            return sb.toString();
        }
    }
}