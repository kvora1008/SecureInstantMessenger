package common;
import java.security.*;
import javax.crypto.*;
import java.util.Base64;

public class Challenge {

    // Method to generate a challenge (can be any string or logic)
    public static String generateChallenge() {
        return "This is a challenge"; // Simple text challenge for demonstration
    }

    // Method to encrypt a challenge using the public key
    public static String encryptChallenge(String challenge, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedChallenge = cipher.doFinal(challenge.getBytes());
        return Base64.getEncoder().encodeToString(encryptedChallenge); // Return the Base64 encoded encrypted message
    }

    // Method to decrypt the challenge using the private key
    public static String decryptMessage(String encryptedChallenge, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedEncryptedChallenge = Base64.getDecoder().decode(encryptedChallenge);
        byte[] decryptedBytes = cipher.doFinal(decodedEncryptedChallenge);
        return new String(decryptedBytes); // Return the decrypted message as a string
    }

    // Method to sign the challenge response (this is part of the authentication)
    public static String signChallengeResponse(String challenge, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(challenge.getBytes());
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes); // Return the Base64 encoded signed response
    }

    // Method to verify the challenge response
    public static boolean verifyChallengeResponse(String challenge, String signedResponse, PublicKey publicKey) throws Exception {
        byte[] signatureBytes = Base64.getDecoder().decode(signedResponse);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(challenge.getBytes());
        return signature.verify(signatureBytes); // Return true if the signature is valid, else false
    }
}
