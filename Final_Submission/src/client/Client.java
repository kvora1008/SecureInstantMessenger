package client;

import java.io.*;
import java.net.*;
import java.security.*;
import common.MessageUtils;
import java.security.interfaces.*;
import java.security.spec.*;
import java.nio.file.*;
import java.util.Arrays;  

class Client {
    private static final String SERVER_ADDRESS = "127.0.0.1";
    private static final int SERVER_PORT_AUTH = 6789;
    private static final int SERVER_CONTROL_PORT = 6791;
	private static UserPrivateKeyManager userPrivateKeyManager;

    @SuppressWarnings("resource")
	public static void main(String argv[]) throws Exception {
        System.out.println("Client is running.");

        try (
            Socket authSocket = new Socket(SERVER_ADDRESS, SERVER_PORT_AUTH);
            Socket controlSocket = new Socket(SERVER_ADDRESS, SERVER_CONTROL_PORT);
            PrintWriter outToServerControl = new PrintWriter(controlSocket.getOutputStream(), true);
			BufferedReader inFromServerControl = new BufferedReader(new InputStreamReader(controlSocket.getInputStream()));
            BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
        ) {
			userPrivateKeyManager = new UserPrivateKeyManager();
			
            System.out.print("Enter your username: ");
            String name = inFromUser.readLine().trim();
			
			ObjectOutputStream out = new ObjectOutputStream(authSocket.getOutputStream());
					
			// Send username to the server
            out.writeObject(name);
            out.flush();
			
			// Send the name to both ports (auth and control)
            outToServerControl.println(name + '\n');
			
            //System.out.println("Sent username: " + name);
			
			ObjectInputStream in = new ObjectInputStream(authSocket.getInputStream());
			
			// Receive the server's initial response
            String serverResponse = (String) in.readObject();
            //System.out.println("Server response: " + serverResponse);
						
			
			if (serverResponse.startsWith("User not found")) {
                // Handle registration
                System.out.println("Registering user...");
                String registrationStatus = (String) in.readObject(); // Receive registration confirmation
                System.out.println(registrationStatus);
            } else if (serverResponse.startsWith("Challenge")) {
                // Handle authentication
                System.out.println("Noted. Proceeding with authentication...");

                // Receive the encrypted challenge from the server
                String encryptedChallenge = (String) in.readObject();
                //System.out.println("Received encrypted challenge: " + encryptedChallenge);

                // Decrypt the challenge using the user's private key
                PrivateKey userPrivateKey = userPrivateKeyManager.loadUserPrivateKey(name);
                if (userPrivateKey == null) {
                    throw new Exception("Private key not found for user: " + name);
                }
                String challenge = MessageUtils.decryptMessage(encryptedChallenge, userPrivateKey);
                //System.out.println("Decrypted challenge: " + challenge);

                // Sign the challenge using the user's private key
                String signedChallenge = MessageUtils.encryptPrivateMessage(challenge, userPrivateKey);  // Signing by encrypting
                //System.out.println("Signed challenge: " + signedChallenge);

                // Send the signed challenge back to the server
                out.writeObject(signedChallenge);
                out.flush();

                // Receive the server's response (authentication result)
                String authStatus = (String) in.readObject();
                //System.out.println("Authentication status: " + authStatus);
            } else {
                // Handle unexpected server responses
                System.out.println("Unexpected server response: " + serverResponse);
            }
			
			//closeAuth(authSocket);
			System.out.println("Authentication completed.");
			
			ClientInputHandler inputHandler = new ClientInputHandler(outToServerControl, inFromUser);
			
			Thread notificationThread = new Thread(new NotificationListener(inFromServerControl, inputHandler));
            notificationThread.start();
					
			System.out.println("Welcome, " + name + "! You are now online and idle.\n");
            System.out.println("Available commands:\n");
            System.out.println("- `list`: List all online users.");
            System.out.println("- `connect <username>`: Request a connection with another user.");
            System.out.println("- `quit`: Exit the chat. \n");
			System.out.println("To close a chat session that is in progress, interrupt manually. \n");

            // Handle user input (listening for commands)
            inputHandler.run();

            System.out.println("Client Terminating Gracefully"); //AKS: Added
            // Cleanup: Stop the notification thread once user quits
            notificationThread.interrupt();
			
		}catch (Exception e) {
            e.printStackTrace();
        }
	}

    private static void closeAuth(Socket authSocket) {
        //System.out.println("Auth connection closed.");
    }  
}	
