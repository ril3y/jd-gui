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
import java.awt.event.ActionListener;
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

            // Always add browser-based VirusTotal lookup (more reliable)
            actions.add(new OpenInVirusTotalAction(api, entry, fragment));

            // Add bulk VirusTotal lookup if API key is configured
            String apiKey = getVirusTotalApiKey(api);
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                actions.add(new BulkCheckVirusTotalAction(api, entry, fragment));
            }

            return actions;
        }
        return Collections.emptyList();
    }

    /**
     * Safely get VirusTotal API key from preferences with environment variable fallback
     * This ensures API keys are never hardcoded and can be securely loaded from .env
     */
    private static String getVirusTotalApiKey(API api) {
        String apiKey = api.getPreferences().get("VirusTotal.apiKey");

        // Fallback to environment variable (secure approach)
        if (apiKey == null || apiKey.trim().isEmpty()) {
            apiKey = System.getenv("VIRUSTOTAL_API_KEY");
        }

        return apiKey;
    }

    /**
     * Shared utility method to generate SHA256 hash for any container entry
     */
    private static String generateSha256Hash(Container.Entry entry) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // Try alternative names
            try {
                digest = MessageDigest.getInstance("SHA256");
            } catch (NoSuchAlgorithmException e2) {
                throw new NoSuchAlgorithmException("SHA-256/SHA256 algorithm not available: " + e.getMessage());
            }
        }

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
                String hash = Sha256HashContextualActionsFactory.generateSha256Hash(entry);

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
    }


    public static class OpenInVirusTotalAction extends AbstractAction {
        protected static final ImageIcon ICON = new ImageIcon(OpenInVirusTotalAction.class.getClassLoader().getResource("org/jd/gui/images/virustotal.png"));

        protected API api;
        protected Container.Entry entry;
        protected String fragment;

        public OpenInVirusTotalAction(API api, Container.Entry entry, String fragment) {
            this.api = api;
            this.entry = entry;
            this.fragment = fragment;

            putValue(GROUP_NAME, "Tools > Hash");
            putValue(NAME, "Open in VirusTotal");
            putValue(SMALL_ICON, ICON);
        }

        public void actionPerformed(ActionEvent e) {
            try {
                // Generate hash
                String hash = Sha256HashContextualActionsFactory.generateSha256Hash(entry);

                // VirusTotal file lookup URL
                String vtUrl = "https://www.virustotal.com/gui/file/" + hash;

                // Copy hash to clipboard for convenience
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(hash), null);

                // Try to open in default browser
                if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                    Desktop.getDesktop().browse(java.net.URI.create(vtUrl));
                    // Browser opened successfully - no dialog needed
                } else {
                    // Fallback: show URL for manual copy (only if browser can't open)
                    String filename = entry.getPath().substring(entry.getPath().lastIndexOf('/') + 1);
                    JOptionPane.showMessageDialog(
                        null,
                        "Cannot open browser automatically.\n\n" +
                        "File: " + filename + "\n" +
                        "SHA256: " + hash + "\n\n" +
                        "Please visit:\n" + vtUrl + "\n\n" +
                        "(Hash and URL copied to clipboard)",
                        "VirusTotal Lookup",
                        JOptionPane.INFORMATION_MESSAGE
                    );

                    // Copy URL to clipboard as well
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(hash + "\n" + vtUrl), null);
                }

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(
                    null,
                    "Error opening VirusTotal: " + ex.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE
                );
            }
        }
    }

    public static class BulkCheckVirusTotalAction extends AbstractAction {
        protected static final ImageIcon ICON = new ImageIcon(BulkCheckVirusTotalAction.class.getClassLoader().getResource("org/jd/gui/images/virustotal.png"));

        protected API api;
        protected Container.Entry entry;
        protected String fragment;


        public BulkCheckVirusTotalAction(API api, Container.Entry entry, String fragment) {
            this.api = api;
            this.entry = entry;
            this.fragment = fragment;

            putValue(GROUP_NAME, "Tools > Hash");
            putValue(NAME, "Bulk Check Selected with VirusTotal");
            putValue(SMALL_ICON, ICON);
        }

        public void actionPerformed(ActionEvent e) {
            // Initialize debug logging
            debugLog("=== BulkCheckVirusTotalAction.actionPerformed() ===");
            debugLog("Action triggered for entry: " + entry.getPath());
            debugLog("Fragment: " + fragment);

            String apiKey = getVirusTotalApiKey(api);
            if (apiKey == null || apiKey.trim().isEmpty()) {
                debugLog("ERROR: No API key configured");
                JOptionPane.showMessageDialog(null,
                    "Please configure your VirusTotal API key in Preferences → VirusTotal",
                    "API Key Required", JOptionPane.WARNING_MESSAGE);
                return;
            }
            debugLog("API key found: " + (apiKey.length() > 10 ? apiKey.substring(0, 10) + "..." : "short key"));

            // Parse multi-select info and prepare for bulk scanning
            if (fragment != null && fragment.contains("#multiselect=")) {
                debugLog("Found multiselect in fragment");

                String multiSelectPart = fragment.substring(fragment.indexOf("#multiselect=") + "#multiselect=".length());
                String[] paths = multiSelectPart.split(";");

                debugLog("Found " + paths.length + " paths in multiselect");

                // Filter to only .class files for VirusTotal scanning
                java.util.List<Container.Entry> classFiles = new java.util.ArrayList<>();
                for (String path : paths) {
                    debugLog("Processing path: '" + path + "'");
                    if (path.trim().endsWith(".class")) {
                        debugLog("Path is a .class file, searching for entry...");
                        Container.Entry foundEntry = findEntryByPath(entry.getContainer().getRoot(), path.trim());
                        if (foundEntry != null) {
                            classFiles.add(foundEntry);
                            debugLog("SUCCESS: Added entry for " + path);
                        } else {
                            debugLog("ERROR: Entry not found for " + path);
                        }
                    } else {
                        debugLog("Skipping non-.class file: " + path);
                    }
                }

                debugLog("Total .class files found: " + classFiles.size());

                if (classFiles.size() > 1) {
                    debugLog("Multiple class files found, showing confirmation dialog");
                    // Show confirmation dialog
                    int confirm = JOptionPane.showConfirmDialog(
                        null,
                        "Bulk scan " + classFiles.size() + " .class files with VirusTotal?",
                        "Bulk VirusTotal Scan",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.QUESTION_MESSAGE
                    );

                    if (confirm == JOptionPane.YES_OPTION) {
                        debugLog("User confirmed bulk scan, starting...");
                        performBulkScan(classFiles);
                    } else {
                        debugLog("User cancelled bulk scan");
                    }
                    return;
                } else if (classFiles.size() == 1) {
                    // Single .class file - proceed with regular single file scan
                    // Fall through to single file logic below
                } else {
                    JOptionPane.showMessageDialog(null,
                        "No .class files found in selection for VirusTotal scanning.",
                        "No Class Files", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
            }

            // Single file scanning options
            String[] options = {
                "Current file only",
                "All .class files in this directory",
                "All .class files in this container",
                "Cancel"
            };

            int choice = JOptionPane.showOptionDialog(
                null,
                "Select files to check with VirusTotal:",
                "VirusTotal Check",
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]
            );

            if (choice == 3 || choice == JOptionPane.CLOSED_OPTION) {
                return; // Cancelled
            }

            // Collect entries to scan based on choice
            java.util.List<Container.Entry> entriesToScan = new java.util.ArrayList<>();

            try {
                if (choice == 0) {
                    // Current file only
                    if (entry.getPath().endsWith(".class")) {
                        entriesToScan.add(entry);
                    } else {
                        JOptionPane.showMessageDialog(null,
                            "Selected file is not a .class file.",
                            "Not a Class File", JOptionPane.INFORMATION_MESSAGE);
                        return;
                    }
                } else if (choice == 1) {
                    // Scan files in same directory
                    Container.Entry parent = entry.getParent();
                    if (parent != null) {
                        collectClassFiles(parent, entriesToScan);
                    } else {
                        collectClassFiles(entry.getContainer().getRoot(), entriesToScan);
                    }
                } else if (choice == 2) {
                    // Scan all .class files in container
                    collectClassFiles(entry.getContainer().getRoot(), entriesToScan);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error collecting files: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (entriesToScan.isEmpty()) {
                JOptionPane.showMessageDialog(null, "No .class files found to scan.", "No Files", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            // Start bulk scanning
            performBulkScan(entriesToScan);
        }

        private void collectClassFiles(Container.Entry entry, java.util.List<Container.Entry> collector) {
            if (entry.isDirectory()) {
                // Recursively collect from subdirectories
                for (Container.Entry child : entry.getChildren()) {
                    collectClassFiles(child, collector);
                }
            } else if (entry.getPath().endsWith(".class")) {
                collector.add(entry);
            }
        }

        private void performBulkScan(java.util.List<Container.Entry> entries) {
            // Create progress dialog
            JDialog progressDialog = new JDialog((java.awt.Frame) null, "Bulk VirusTotal Scan", true);
            progressDialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);

            JPanel panel = new JPanel(new BorderLayout(10, 10));
            panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

            JLabel statusLabel = new JLabel("Scanning " + entries.size() + " files...");
            statusLabel.setHorizontalAlignment(JLabel.CENTER);
            panel.add(statusLabel, BorderLayout.NORTH);

            JProgressBar progressBar = new JProgressBar(0, entries.size());
            progressBar.setStringPainted(true);

            JPanel centerPanel = new JPanel(new BorderLayout(10, 10));
            centerPanel.add(progressBar, BorderLayout.NORTH);

            // Results table
            String[] columnNames = {"File", "SHA256", "Detections", "Status"};
            javax.swing.table.DefaultTableModel tableModel = new javax.swing.table.DefaultTableModel(columnNames, 0) {
                @Override
                public boolean isCellEditable(int row, int column) { return false; }
            };
            JTable resultsTable = new JTable(tableModel);
            resultsTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);

            // Set monospaced font for SHA256 column
            resultsTable.getColumnModel().getColumn(1).setCellRenderer(new javax.swing.table.DefaultTableCellRenderer() {
                @Override
                public java.awt.Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                    java.awt.Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                    c.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, c.getFont().getSize()));
                    return c;
                }
            });
            JScrollPane tableScrollPane = new JScrollPane(resultsTable);
            tableScrollPane.setPreferredSize(new Dimension(700, 300));
            centerPanel.add(tableScrollPane, BorderLayout.CENTER);

            panel.add(centerPanel, BorderLayout.CENTER);

            JButton cancelButton = new JButton("Cancel");
            JPanel buttonPanel = new JPanel();
            buttonPanel.add(cancelButton);
            panel.add(buttonPanel, BorderLayout.SOUTH);

            progressDialog.setContentPane(panel);
            progressDialog.pack();
            progressDialog.setLocationRelativeTo(null);

            // Background worker for bulk scanning
            SwingWorker<Void, BulkScanResult> worker = new SwingWorker<Void, BulkScanResult>() {
                private volatile boolean cancelled = false;

                @Override
                protected Void doInBackground() throws Exception {
                    String apiKey = getVirusTotalApiKey(api);
                    VirusTotalClient client = new VirusTotalClient();

                    for (int i = 0; i < entries.size() && !cancelled && !isCancelled(); i++) {
                        Container.Entry entry = entries.get(i);

                        String filename = entry.getPath().substring(entry.getPath().lastIndexOf('/') + 1);

                        try {
                            // Try to generate hash
                            String hash = Sha256HashContextualActionsFactory.generateSha256Hash(entry);

                            // Publish progress
                            publish(new BulkScanResult(filename, hash, "Scanning...", 0, false));

                            // Check with VirusTotal
                            VirusTotalClient.VirusTotalResponse response = client.checkHash(hash, apiKey);

                            String status;
                            int detections = 0;
                            boolean isMalicious = false;

                            if (response.hasError() && response.getErrorMessage().contains("not found")) {
                                // Hash not found in VirusTotal database
                                status = "Not found on VT";
                                detections = -1; // Use -1 for not found on VT
                            } else if (response.hasError()) {
                                status = "Error: " + response.getErrorMessage();
                                detections = 0;
                            } else if (!response.isFound()) {
                                status = "Not found on VT";
                                detections = -1; // Use -1 for not found on VT
                            } else {
                                detections = response.getMalicious() + response.getSuspicious();
                                isMalicious = response.isMalicious();
                                status = isMalicious ? "⚠️ MALICIOUS (" + detections + " detections)" : "✅ Clean";
                            }

                            // Publish result
                            publish(new BulkScanResult(filename, hash, status, detections, isMalicious));

                            // Rate limiting - use configured rate limit
                            if (i < entries.size() - 1) {
                                String rateLimitStr = api.getPreferences().get("VirusTotal.rateLimitSeconds");
                                double rateLimitSeconds = 1.0; // Default
                                try {
                                    if (rateLimitStr != null && !rateLimitStr.trim().isEmpty()) {
                                        rateLimitSeconds = Double.parseDouble(rateLimitStr);
                                    }
                                } catch (NumberFormatException e) {
                                    // Use default
                                }
                                int delayMs = (int)(rateLimitSeconds * 1000);
                                Thread.sleep(delayMs);
                            }

                        } catch (Exception e) {
                            // Hash generation failed - show error but continue with other files
                            publish(new BulkScanResult(filename, "Hash Error", "Cannot generate SHA-256: " + e.getMessage(), 0, false));
                        }

                        // Update progress
                        final int progress = i + 1;
                        SwingUtilities.invokeLater(() -> {
                            progressBar.setValue(progress);
                            progressBar.setString(progress + " / " + entries.size());
                            statusLabel.setText("Scanned " + progress + " of " + entries.size() + " files");
                        });
                    }

                    return null;
                }

                @Override
                protected void process(java.util.List<BulkScanResult> chunks) {
                    for (BulkScanResult result : chunks) {
                        // Update existing row or add new row
                        boolean found = false;
                        for (int i = 0; i < tableModel.getRowCount(); i++) {
                            if (result.filename.equals(tableModel.getValueAt(i, 0))) {
                                tableModel.setValueAt(result.status, i, 3);
                                tableModel.setValueAt(result.detections == -1 ? "-1" : result.detections, i, 2);
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            tableModel.addRow(new Object[]{
                                result.filename,
                                result.hash,
                                result.detections == -1 ? "-1" : result.detections,
                                result.status
                            });
                        }

                        // Color malicious files
                        if (result.isMalicious && tableModel.getRowCount() > 0) {
                            int lastRow = tableModel.getRowCount() - 1;
                            // Note: Row coloring would need custom renderer - for now we use emoji indicators
                        }
                    }
                }

                @Override
                protected void done() {
                    cancelButton.setText("Close");
                    statusLabel.setText("Scan completed - " + entries.size() + " files checked");
                    progressBar.setString("Complete");

                    // Count results
                    int maliciousCount = 0;
                    for (int i = 0; i < tableModel.getRowCount(); i++) {
                        String status = tableModel.getValueAt(i, 3).toString();
                        if (status.contains("MALICIOUS")) {
                            maliciousCount++;
                        }
                    }

                    if (maliciousCount > 0) {
                        statusLabel.setText("⚠️ SCAN COMPLETE - " + maliciousCount + " malicious files found!");
                        statusLabel.setForeground(java.awt.Color.RED);
                    } else {
                        statusLabel.setText("✅ Scan completed - All files appear clean");
                        statusLabel.setForeground(java.awt.Color.BLUE);
                    }
                }

                public void cancelWork() {
                    cancelled = true;
                    cancel(true);
                }
            };

            cancelButton.addActionListener(e -> {
                if (worker.isDone()) {
                    progressDialog.dispose();
                } else {
                    worker.cancel(true);
                    progressDialog.dispose();
                }
            });

            progressDialog.addWindowListener(new java.awt.event.WindowAdapter() {
                @Override
                public void windowClosing(java.awt.event.WindowEvent e) {
                    if (!worker.isDone()) {
                        worker.cancel(true);
                    }
                    progressDialog.dispose();
                }
            });

            worker.execute();
            progressDialog.setVisible(true);
        }

        private void debugLog(String message) {
            try {
                java.io.FileWriter writer = new java.io.FileWriter("jd-gui-virustotal-debug.log", true);
                java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                writer.write("[" + sdf.format(new java.util.Date()) + "] " + message + "\n");
                writer.close();
                System.out.println("VT-DEBUG: " + message); // Also log to console
            } catch (Exception e) {
                System.err.println("Debug log error: " + e.getMessage());
            }
        }

        private java.util.List<Container.Entry> parseMultiSelectFromFragment(String fragment) {
            java.util.List<Container.Entry> entries = new java.util.ArrayList<>();

            if (fragment != null && fragment.contains("#multiselect=")) {
                String multiSelectPart = fragment.substring(fragment.indexOf("#multiselect=") + "#multiselect=".length());
                String[] paths = multiSelectPart.split(";");

                for (String path : paths) {
                    if (!path.trim().isEmpty()) {
                        Container.Entry found = findEntryByPath(entry.getContainer().getRoot(), path.trim());
                        if (found != null) {
                            entries.add(found);
                        }
                    }
                }
            }

            return entries;
        }

        private java.util.List<Container.Entry> getSelectedTreeEntries() {
            java.util.List<Container.Entry> entries = new java.util.ArrayList<>();

            // Try to get selected paths from API preferences (if stored by tree component)
            String selectedPaths = api.getPreferences().get("tree.selectedPaths");
            if (selectedPaths != null && !selectedPaths.trim().isEmpty()) {
                String[] paths = selectedPaths.split(";");
                for (String pathStr : paths) {
                    if (!pathStr.trim().isEmpty()) {
                        // Try to find the entry with this path in the current container
                        Container.Entry foundEntry = findEntryByPath(entry.getContainer().getRoot(), pathStr.trim());
                        if (foundEntry != null) {
                            entries.add(foundEntry);
                        }
                    }
                }
                // Clear the stored paths after use
                api.getPreferences().put("tree.selectedPaths", "");
            }

            // If no stored selections, return single current entry
            if (entries.isEmpty()) {
                entries.add(entry);
            }

            return entries;
        }

        private Container.Entry findEntryByPath(Container.Entry root, String targetPath) {
            debugLog("Searching for: '" + targetPath + "' starting from: '" + root.getPath() + "'");

            // Quick check: if root matches, return it
            if (root.getPath().equals(targetPath)) {
                debugLog("Found exact match at root");
                return root;
            }

            // For efficiency, let's limit the search to the current directory level first
            // Since we're looking for files in the same container
            java.util.List<Container.Entry> toSearch = new java.util.ArrayList<>();
            toSearch.add(root);

            int maxDepth = 10; // Prevent infinite recursion
            int currentDepth = 0;

            while (!toSearch.isEmpty() && currentDepth < maxDepth) {
                java.util.List<Container.Entry> nextLevel = new java.util.ArrayList<>();

                for (Container.Entry current : toSearch) {
                    debugLog("Checking entry: '" + current.getPath() + "'");

                    if (current.getPath().equals(targetPath)) {
                        debugLog("Found match: " + targetPath);
                        return current;
                    }

                    // Check direct children
                    for (Container.Entry child : current.getChildren()) {
                        if (child.getPath().equals(targetPath)) {
                            debugLog("Found match in children: " + targetPath);
                            return child;
                        }

                        // Add to next level if it's a directory
                        if (child.isDirectory()) {
                            nextLevel.add(child);
                        }
                    }
                }

                toSearch = nextLevel;
                currentDepth++;
                debugLog("Searched depth " + currentDepth + ", " + nextLevel.size() + " entries for next level");
            }

            debugLog("Entry not found after search: " + targetPath);
            return null;
        }
    }

    // Helper class for bulk scan results
    private static class BulkScanResult {
        final String filename;
        final String hash;
        final String status;
        final int detections;
        final boolean isMalicious;

        BulkScanResult(String filename, String hash, String status, int detections, boolean isMalicious) {
            this.filename = filename;
            this.hash = hash;
            this.status = status;
            this.detections = detections;
            this.isMalicious = isMalicious;
        }
    }
}