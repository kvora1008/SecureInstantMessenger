package common;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import javax.crypto.Cipher;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MessageUtils {

    // Method to encrypt the message with the public key
    public static String encryptMessage(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        
        // Return the encrypted message as a Base64-encoded string
        return Base64.getEncoder().encodeToString(encryptedMessage);  // Corrected encoding of byte[] to Base64
    }
    
    // Method to encrypt the message with the private key
    public static String encryptPrivateMessage(String message, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        
        // Return the encrypted message as a Base64-encoded string
        return Base64.getEncoder().encodeToString(encryptedMessage);  // Corrected encoding of byte[] to Base64
    }

    // Method to decrypt the message with the private key
    public static String decryptMessage(String encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);  // Decode from Base64 to byte[]
        byte[] decryptedMessage = cipher.doFinal(decodedMessage);
        
        return new String(decryptedMessage);  // Convert byte[] to String
    }
    
    // Method to decrypt the message with the public key
    public static String decryptPublicMessage(String encryptedMessage, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);  // Decode from Base64 to byte[]
        byte[] decryptedMessage = cipher.doFinal(decodedMessage);
        
        return new String(decryptedMessage);  // Convert byte[] to String
    }
	
	// Derive an AES encryption key from a master key using SHA-256
    public static SecretKey deriveKey(byte[] masterKey) throws Exception { //AKS: Added. Shared secret from server is master key
        // Hash the master key using SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hashedKey = sha256.digest(masterKey);

        // Use the first 16 bytes of the hash for AES (128-bit key)
        return new SecretKeySpec(hashedKey, 0, 16, "AES");
    }

    // Encrypt a message using AES
    public static String encrypt(String message, SecretKey key) throws Exception {//AKS: Added
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes); // Encode to Base64 for easy storage
    }

    // Decrypt a message using AES
    public static String decrypt(String encryptedMessage, SecretKey key) throws Exception {//AKS: Added
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedMessage); // Decode from Base64
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }
		
}


	
