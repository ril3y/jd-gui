/*
 * Copyright (c) 2008-2019 Emmanuel Dupuy.
 * This project is distributed under the GPLv3 license.
 * This is a Copyleft license that gives the user the right to use,
 * copy and modify the code freely for non-commercial purposes.
 */

package org.jd.gui.service.actions;

import org.jd.gui.api.API;
import org.jd.gui.api.model.Container;
import org.jd.gui.spi.ContextualActionsFactory;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.event.ActionEvent;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;

public class SaveAsContextualActionsFactory implements ContextualActionsFactory {

    public Collection<Action> make(API api, Container.Entry entry, String fragment) {
        // Show Save As for any file
        if (entry != null && !entry.isDirectory()) {
            Collection<Action> actions = new ArrayList<Action>();
            actions.add(new SaveAsAction(api, entry, fragment));
            return actions;
        }
        return java.util.Collections.emptyList();
    }

    public static class SaveAsAction extends AbstractAction {
        protected static final ImageIcon ICON = new ImageIcon(SaveAsAction.class.getClassLoader().getResource("org/jd/gui/images/save.png"));

        protected API api;
        protected Container.Entry entry;
        protected String fragment;

        public SaveAsAction(API api, Container.Entry entry, String fragment) {
            this.api = api;
            this.entry = entry;
            this.fragment = fragment;

            putValue(GROUP_NAME, "File Operations");
            putValue(NAME, "Save As...");
            putValue(SMALL_ICON, ICON);
        }

        public void actionPerformed(ActionEvent e) {
            try {
                // Get the filename from the entry path
                String originalPath = entry.getPath();
                String filename = originalPath.substring(originalPath.lastIndexOf('/') + 1);

                // Create file chooser
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Save File As");
                fileChooser.setSelectedFile(new File(filename));

                // Add file filters based on extension
                String extension = "";
                int dotIndex = filename.lastIndexOf('.');
                if (dotIndex > 0) {
                    extension = filename.substring(dotIndex + 1).toLowerCase();

                    switch (extension) {
                        case "class":
                            fileChooser.setFileFilter(new FileNameExtensionFilter("Java Class Files (*.class)", "class"));
                            break;
                        case "java":
                            fileChooser.setFileFilter(new FileNameExtensionFilter("Java Source Files (*.java)", "java"));
                            break;
                        case "jar":
                            fileChooser.setFileFilter(new FileNameExtensionFilter("JAR Files (*.jar)", "jar"));
                            break;
                        case "xml":
                            fileChooser.setFileFilter(new FileNameExtensionFilter("XML Files (*.xml)", "xml"));
                            break;
                        case "properties":
                            fileChooser.setFileFilter(new FileNameExtensionFilter("Properties Files (*.properties)", "properties"));
                            break;
                        default:
                            fileChooser.setFileFilter(new FileNameExtensionFilter(extension.toUpperCase() + " Files (*." + extension + ")", extension));
                            break;
                    }
                }

                // Show save dialog
                int result = fileChooser.showSaveDialog(null);

                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();

                    // Check if file exists and confirm overwrite
                    if (selectedFile.exists()) {
                        int confirmResult = JOptionPane.showConfirmDialog(
                            null,
                            "The file '" + selectedFile.getName() + "' already exists.\nDo you want to overwrite it?",
                            "File Exists",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.QUESTION_MESSAGE
                        );

                        if (confirmResult != JOptionPane.YES_OPTION) {
                            return; // User cancelled
                        }
                    }

                    // Save the file
                    saveFileWithVerification(entry, selectedFile);
                }

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(
                    null,
                    "Error saving file: " + ex.getMessage(),
                    "Save Error",
                    JOptionPane.ERROR_MESSAGE
                );
            }
        }

        private void saveFileWithVerification(Container.Entry entry, File targetFile) throws IOException, NoSuchAlgorithmException {
            // Calculate original hash
            String originalHash = calculateSHA256(entry);

            // Save the file
            try (InputStream inputStream = entry.getInputStream();
                 FileOutputStream outputStream = new FileOutputStream(targetFile)) {

                byte[] buffer = new byte[8192];
                int bytesRead;
                long totalBytesWritten = 0;

                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                    totalBytesWritten += bytesRead;
                }

                outputStream.flush();

                // Verify the saved file by calculating its hash
                String savedHash = calculateSHA256FromFile(targetFile);

                // Compare hashes
                if (!originalHash.equals(savedHash)) {
                    // Delete the corrupted file
                    targetFile.delete();
                    throw new IOException("File integrity verification failed! Hashes do not match.\n" +
                                        "Original: " + originalHash + "\n" +
                                        "Saved: " + savedHash);
                }

                // Show success message with hash verification
                JOptionPane.showMessageDialog(
                    null,
                    "File saved successfully!\n\n" +
                    "Path: " + targetFile.getAbsolutePath() + "\n" +
                    "Size: " + totalBytesWritten + " bytes\n" +
                    "SHA256: " + originalHash + "\n" +
                    "✅ Hash verification passed",
                    "Save Complete",
                    JOptionPane.INFORMATION_MESSAGE
                );

            } catch (IOException | NoSuchAlgorithmException ex) {
                // Clean up on error
                if (targetFile.exists()) {
                    targetFile.delete();
                }
                throw ex;
            }
        }

        private String calculateSHA256(Container.Entry entry) throws IOException, NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            try (InputStream inputStream = entry.getInputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;

                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            byte[] hashBytes = digest.digest();
            StringBuilder hexString = new StringBuilder();

            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        }

        private String calculateSHA256FromFile(File file) throws IOException, NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] buffer = new byte[8192];
                int bytesRead;

                while ((bytesRead = fis.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            byte[] hashBytes = digest.digest();
            StringBuilder hexString = new StringBuilder();

            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        }
    }
}