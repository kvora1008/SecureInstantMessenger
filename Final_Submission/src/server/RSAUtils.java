package server;

import java.security.*;
import javax.crypto.Cipher;
import java.util.Arrays;

public class RSAUtils {

    // Generate RSA key pair (public/private key)
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);  // 2048-bit key size
        return keyPairGenerator.generateKeyPair();
    }

    // Encrypt a message using the provided public key
    public static byte[] encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    // Decrypt a message using the provided private key
    public static String decrypt(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    // Sign a message using the private key
    public static byte[] sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    // Verify the signature using the public key
    public static boolean verify(String message, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        return signature.verify(signatureBytes);
    }
	
	public static byte[] generateSessionKey(byte[] pk1, byte [] pk2) throws Exception{
		byte[] nonce = new byte[16];
        new java.util.Random().nextBytes(nonce);

        // Get current time in bytes (e.g., long time in milliseconds)
        long currentTime = System.currentTimeMillis();
        byte[] timeBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            timeBytes[i] = (byte) (currentTime >> (i * 8));
        }

        // Concatenate pk1, pk2, nonce, and timeBytes
        byte[] masterKey = new byte[pk1.length + pk2.length + nonce.length + timeBytes.length];
        System.arraycopy(pk1, 0, masterKey, 0, pk1.length);
        System.arraycopy(pk2, 0, masterKey, pk1.length, pk2.length);
        System.arraycopy(nonce, 0, masterKey, pk1.length + pk2.length, nonce.length);
        System.arraycopy(timeBytes, 0, masterKey, pk1.length + pk2.length + nonce.length, timeBytes.length);

        // Derive 128-bit session key using SHA-256 and take the first 16 bytes
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(masterKey);

        return Arrays.copyOfRange(hash, 0, 16); // 128-bit session key
	}
}
