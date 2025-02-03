package server;

import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;

import common.KeyGenerator;

public class ChallengeManager {

    private String originalChallenge;  // Class-level variable to store the original challenge

    public ChallengeManager() throws Exception {
        // Generate or load the server's RSA key pair
        KeyPair serverKeyPair = KeyGenerator.generateKeyPair();
        serverKeyPair.getPrivate();
        serverKeyPair.getPublic();
    }

    public String generateChallenge(PublicKey userPublicKey) throws Exception {
        // Generate a random challenge (could be a simple string or number)
        originalChallenge = "random_challenge_" + System.currentTimeMillis();
        // Encrypt challenge using user's public key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, userPublicKey);
        byte[] encryptedChallenge = cipher.doFinal(originalChallenge.getBytes());
        // Return the encrypted challenge as a Base64 encoded string
        return Base64.getEncoder().encodeToString(encryptedChallenge);
    }
    
    // Method to access the original challenge later
    public String getOriginalChallenge() {
        return originalChallenge;
    }

    public boolean verifyChallengeResponse(String signedResponse, String challenge, PublicKey userPublicKey) throws Exception {
        // Decode the Base64 encoded response
        byte[] encryptedResponse = Base64.getDecoder().decode(signedResponse);
        
        // Decrypt the response with the user's public key (not private key)
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, userPublicKey); // Use the user's public key to verify the response
        byte[] decryptedResponse = cipher.doFinal(encryptedResponse);
        
        String decryptedChallenge = new String(decryptedResponse);
        //System.out.println("Signed challenge: " + signedResponse);
        //System.out.println("Original challenge: " + challenge);
        //System.out.println("Decrypted challenge: " + decryptedChallenge);
        //System.out.println("Comparison result: " + decryptedChallenge.equals(challenge));

        return decryptedChallenge.equals(challenge);
    }
}



