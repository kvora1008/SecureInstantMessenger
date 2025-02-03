package server;

import common.KeyGenerator;
import common.MessageUtils;

import client.UserPrivateKeyManager;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.security.*;
import java.nio.file.*;
import java.util.stream.Collectors;


class Server {
    private static final int SERVER_PORT_AUTH = 6789;
    private static final int CONTROL_PORT = 6791;

    private static List<AuthHandler> authClients = new ArrayList<>();  // Keep this list for authentication handlers
    private static Map<String, String> clients = new HashMap<>();  // Changed to Map for client status tracking
    private static ChallengeManager challengeManager;
    private static UserPublicKeyManager userPublicKeyManager;
    private static UserPrivateKeyManager userPrivateKeyManager;
    private static ExecutorService threadPool;
	private static final ConcurrentHashMap<String, User> users = new ConcurrentHashMap<>();

    public static void main(String args[]) throws Exception {
        System.out.println("Server is running.");
		challengeManager = new ChallengeManager();
        userPublicKeyManager = new UserPublicKeyManager();
        userPrivateKeyManager = new UserPrivateKeyManager();
        threadPool = Executors.newFixedThreadPool(10); 

        try (ServerSocket authServerSocket = new ServerSocket(SERVER_PORT_AUTH);
             ServerSocket controlServerSocket = new ServerSocket(CONTROL_PORT)) {

            while (true) {
                // Accept incoming connections for auth and control
                Socket authSocket = authServerSocket.accept();
                BufferedReader inFromClientAuth = new BufferedReader(new InputStreamReader(authSocket.getInputStream()));
                DataOutputStream outToClientAuth = new DataOutputStream(authSocket.getOutputStream());

                Socket controlSocket = controlServerSocket.accept();
				BufferedReader inFromClientControl = new BufferedReader(new InputStreamReader(controlSocket.getInputStream()));
                DataOutputStream outToClientControl = new DataOutputStream(controlSocket.getOutputStream());
                

                // Get client name
                //String nameAuth = inFromClientAuth.readLine();
                String nameControl = inFromClientControl.readLine();
				System.out.println("New connection established with: "+nameControl);
				new Thread(new ConnectionManager(controlSocket, users, nameControl)).start();

                // Log client connection
                //logToClientFile("Client connected: " + nameControl);
                //System.out.println("Client connected: " + nameControl);

                // Create and start AuthHandler for authentication
                AuthHandler authHandler = new AuthHandler(authSocket);
                authClients.add(authHandler);  // No change here
                threadPool.submit((authHandler));
				
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void closeAuth(Socket authSocket) {
        try {
            if (authSocket != null) {
                authSocket.close();
                System.out.println("Auth connection closed.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Log math-related activities
    private static void logToAuthFile(String message) {
        try (FileWriter fw = new FileWriter("auth.log", true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            out.println("[" + new Date() + "] " + message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // AuthHandler: Handle authentication for clients
    static class AuthHandler implements Runnable{
        //private String nameAuth;
        private Socket authSocket;
        private ObjectInputStream in;
        private ObjectOutputStream out;
        private Date connectionStartTime;

        public AuthHandler(Socket authSocket
                         ) 
		{
			try{
				//this.nameAuth = nameAuth;
				this.authSocket = authSocket;
				this.in = new ObjectInputStream(authSocket.getInputStream());
				this.out = new ObjectOutputStream(authSocket.getOutputStream());
				this.connectionStartTime = new Date();
			}catch (IOException e)
			{
				e.printStackTrace();
			}
        }
		@Override
        public void run() 
		{
            try (FileWriter fw = new FileWriter("auth.log", true);
                 BufferedWriter bw = new BufferedWriter(fw);
                 PrintWriter outLog = new PrintWriter(bw)) 
			{
					 
				String username = (String) in.readObject();
				//System.out.println("Received username:" + username);
				
				PublicKey userPublicKey = userPublicKeyManager.loadUserPublicKey(username);
                // Auth question handler loop
				if (userPublicKey != null) 
				{
                    // Generate and encrypt challenge
//                    String challenge = Challenge.generateChallenge();
                    String encryptedChallenge = challengeManager.generateChallenge(userPublicKey);
                    out.writeObject("Challenge generated.");
                    out.writeObject(encryptedChallenge);  // Send encrypted challenge to the client
                    out.flush();
                    
                    String originalChallenge = challengeManager.getOriginalChallenge();

                    // Receive signed response from client
                    String signedResponse = (String) in.readObject();
                    //System.out.println("Received response:" + signedResponse);
                    String convert = MessageUtils.decryptPublicMessage(signedResponse, userPublicKey);
                    //System.out.println("Decrypted challenge:" + convert);
                    try 
					{
                        if (challengeManager.verifyChallengeResponse(signedResponse, originalChallenge, userPublicKey)) {
                            out.writeObject("You are authenticated to the server.");
							logToAuthFile( username+ " has been authenticated successfully.");
                        } else {
                        	//System.out.println("Sent challenge:" + originalChallenge);
                            throw new Exception("Challenge verification failed.");
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        //System.out.println("Sent challenge:" + originalChallenge);
                        out.writeObject("Challenge failed. Registering user...");
						
                        // Registration logic here
                      generateKPAndRegister(username);
                      out.writeObject("You are registered to the server.");
					  logToAuthFile( "Challenge verification failed."+ username+ " has been registered as a new user.");
                    }
                } else {
                    // If user is not found, register the user
                    out.writeObject("User not found. Registering user...");
                    generateKPAndRegister(username);
                    out.writeObject("You are registered to the server.");
					logToAuthFile( "No such user exists. "+username+ " has been registered as a new user.");
                }
            } catch (Exception e) {
                System.out.println("Error encountered during authentication. Username may have an associated stale key. Try a different username.");
				//e.printStackTrace();
            } 
			closeAuth(authSocket);
		}
		
	}
	private static void generateKPAndRegister(String username) throws Exception{
		KeyPair userKeyPair = KeyGenerator.generateKeyPair();
		userPublicKeyManager.storeUserPublicKey(username, userKeyPair.getPublic());
		userPrivateKeyManager.storeUserPrivateKey(username, userKeyPair.getPrivate());
	}
}
