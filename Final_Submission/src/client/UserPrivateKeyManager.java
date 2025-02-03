package client;

import java.io.*;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import common.KeyGenerator;

public class UserPrivateKeyManager {

    private static final String USER_KEY_PATH = "resources/userPrivateKeys/";

    // Store the user's private key in a local file
    public void storeUserPrivateKey(String username, PrivateKey privateKey) throws IOException {
        File dir = new File(USER_KEY_PATH);
        if (!dir.exists()) {
            dir.mkdirs(); // Create directory if it doesn't exist
        }

        // Save user's private key to a file
        try (FileWriter writer = new FileWriter(USER_KEY_PATH + username + "_private.key")) {
            writer.write(KeyGenerator.encodeKey(privateKey)); // Save as Base64 string
        }
    }

    // Load the user's private key from a file
    public PrivateKey loadUserPrivateKey(String username) throws Exception {
        Path filePath = Paths.get(USER_KEY_PATH + username + "_private.key");
        if (Files.exists(filePath)) {
            String keyStr = new String(Files.readAllBytes(filePath));
            return (PrivateKey) KeyGenerator.decodeKey(keyStr, true);  // Decode as private key
        }
        return null;  // No private key found
    }

    // Generate and store keys for a user (if not already generated)
    public KeyPair generateAndStoreKeys(String username) throws Exception {
        if (loadUserPrivateKey(username) != null) {
            System.out.println("Private key already exists for user: " + username);
            return null; // Keys already exist
        }

        KeyPair keyPair = KeyGenerator.generateKeyPair(); // Generate new RSA key pair
        storeUserPrivateKey(username, keyPair.getPrivate());
        System.out.println("Private key stored for user: " + username);
        return keyPair; // Return the generated key pair
    }
}


