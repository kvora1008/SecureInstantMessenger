package common;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyGenerator {

    // Method to generate a new RSA KeyPair
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);  // Set key size (2048 bits for RSA)
        return keyPairGenerator.generateKeyPair();  // Return the generated key pair
    }

    // Method to decode a Base64-encoded key string into either PrivateKey or PublicKey
    public static Key decodeKey(String encodedKey, boolean isPrivateKey) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        if (isPrivateKey) {
            // Decode as PrivateKey
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            return keyFactory.generatePrivate(keySpec);
        } else {
            // Decode as PublicKey
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
            return keyFactory.generatePublic(keySpec);
        }
    }

    // Utility method to encode a key into a Base64 string (for storage or transmission)
    public static String encodeKey(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
}
