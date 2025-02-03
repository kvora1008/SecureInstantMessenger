import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    private static final String SHARED_KEY = "SharedSecretKey";
    private static final String HMAC_KEY = "HMACSecretKey";
    private static final ExecutorService threadPool = Executors.newCachedThreadPool();

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Are you hosting the chat? (yes/no):");
        String response = scanner.nextLine();

        if (response.equalsIgnoreCase("yes")) {
            startServer();
        } else {
            System.out.println("Enter the host's IP address:");
            String hostAddress = scanner.nextLine();
            System.out.println("Enter the host's port:");
            int hostPort = scanner.nextInt();
            connectToPeer(hostAddress, hostPort);
        }
    }

    private static void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(0)) { // Bind to port 0 for dynamic port assignment
            int assignedPort = serverSocket.getLocalPort();
            System.out.println("Hosting chat on port " + assignedPort);
            System.out.println("Share this port with your peers to connect.");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Peer connected: " + clientSocket.getInetAddress());
                threadPool.execute(() -> handlePeer(clientSocket));
            }
        } catch (IOException e) {
            System.err.println("Error hosting chat: " + e.getMessage());
        }
    }

    private static void connectToPeer(String hostAddress, int port) {
        try (Socket socket = new Socket(hostAddress, port)) {
            System.out.println("Connected to peer at " + hostAddress + ":" + port);
            handlePeer(socket);
        } catch (IOException e) {
            System.err.println("Error connecting to peer: " + e.getMessage());
        }
    }

    private static void handlePeer(Socket socket) {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            Scanner scanner = new Scanner(System.in)
        ) {
            Thread listenerThread = new Thread(() -> {
                try {
                    String incomingMessage;
                    while ((incomingMessage = in.readLine()) != null) {
                        String[] parts = incomingMessage.split("::");
                        if (parts.length == 3) {
                            String nonce = parts[0];
                            String receivedCiphertext = parts[1];
                            String receivedMac = parts[2];

                            String calculatedMac = generateMac(nonce + "::" + receivedCiphertext);
                            if (calculatedMac.equals(receivedMac)) {
                                String decryptedMessage = decryptMessage(receivedCiphertext, nonce);
                                System.out.println("[Peer]: " + decryptedMessage);
                            } else {
                                System.err.println("Message integrity compromised.");
                            }
                        } else {
                            System.err.println("Invalid message format received.");
                        }
                    }
                } catch (IOException e) {
                    System.err.println("Connection closed.");
                }
            });
            listenerThread.start();

            System.out.println("Start chatting! Type your messages below:");
            while (true) {
                String message = scanner.nextLine();
                String nonce = generateNonce();
                String encryptedMessage = encryptMessage(message, nonce);
                String mac = generateMac(nonce + "::" + encryptedMessage);

                out.println(nonce + "::" + encryptedMessage + "::" + mac);
            }
        } catch (IOException e) {
            System.err.println("Chat error: " + e.getMessage());
        }
    }

    private static String encryptMessage(String message, String nonce) {
        try {
            byte[] keyBytes = generateHash(SHARED_KEY, nonce);
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedBytes = xorBytes(messageBytes, keyBytes);
            return bytesToHex(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Encryption error", e);
        }
    }

    private static String decryptMessage(String ciphertext, String nonce) {
        try {
            byte[] encryptedBytes = hexToBytes(ciphertext);
            byte[] keyBytes = generateHash(SHARED_KEY, nonce);
            byte[] decryptedBytes = xorBytes(encryptedBytes, keyBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption error", e);
        }
    }

    private static String generateMac(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(HMAC_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] macBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(macBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error generating MAC", e);
        }
    }

    private static byte[] generateHash(String key, String nonce) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String combined = key + (nonce != null ? nonce : "");
        return md.digest(combined.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i % b.length]);
        }
        return result;
    }

    private static String generateNonce() {
        int nonceLength = 16;
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder nonce = new StringBuilder(nonceLength);
        for (int i = 0; i < nonceLength; i++) {
            nonce.append(characters.charAt(random.nextInt(characters.length())));
        }
        return nonce.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
