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
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;

public class Sha256HashContextualActionsFactory implements ContextualActionsFactory {

    public Collection<Action> make(API api, Container.Entry entry, String fragment) {
        // Only show for class files
        if (entry != null && entry.getPath().endsWith(".class")) {
            return Collections.<Action>singletonList(new GenerateSha256Action(api, entry, fragment));
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
}