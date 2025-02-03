package server;

import java.io.*;
import java.nio.file.*;
import java.security.PublicKey;
import common.KeyGenerator;

public class UserPublicKeyManager {

    private static final String USER_KEY_PATH = "resources/userKeys/";

    // Store the user's public key in a local file
    public void storeUserPublicKey(String username, PublicKey publicKey) throws IOException {
        File dir = new File(USER_KEY_PATH);
        if (!dir.exists()) {
            dir.mkdirs(); // Create directory if it doesn't exist
        }

        // Save user's public key to a file
        try (FileWriter writer = new FileWriter(USER_KEY_PATH + username + "_public.key")) {
            writer.write(KeyGenerator.encodeKey(publicKey)); // Save as Base64 string
        }
    }

    // Load the user's public key from a file
    public PublicKey loadUserPublicKey(String username) throws Exception {
        Path filePath = Paths.get(USER_KEY_PATH + username + "_public.key");
        if (Files.exists(filePath)) {
            String keyStr = new String(Files.readAllBytes(filePath));
            return (PublicKey) KeyGenerator.decodeKey(keyStr, false);  // Decode as public key
        }
        return null;  // No public key found
    }
}
