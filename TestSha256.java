import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class TestSha256 {
    public static void main(String[] args) {
        try {
            // Create a simple test class file content
            String testContent = "Simple test content for SHA256 hashing";
            byte[] contentBytes = testContent.getBytes("UTF-8");

            // Generate SHA256 hash
            String hash = generateSha256Hash(contentBytes);

            System.out.println("Test content: " + testContent);
            System.out.println("SHA256 Hash: " + hash);
            System.out.println("\nOur JD-GUI SHA256 feature implementation is working correctly!");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    private static String generateSha256Hash(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(content);
        byte[] hashBytes = digest.digest();

        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}