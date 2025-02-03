package server;

import java.io.*;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;
import java.security.PublicKey;
import java.util.Arrays;


public class ConnectionManager implements Runnable {

    private final Socket clientSocket;  //AKS: Control Socket on the Server
    private final ConcurrentHashMap<String, User> users;
    private User currentUser; //chat request is targeted at this user
    private User pendingConnectionUser;
    private PrintWriter out;
    private BufferedReader in;
	private String username;
	private static UserPublicKeyManager userPublicKeyManager;
	private User requesterUser=null; //chat initiating user

    public ConnectionManager(Socket clientSocket, ConcurrentHashMap<String, User> users,String username) {
        this.clientSocket = clientSocket;
        this.users = users;
		this.username=username;
    }

    @Override
    public void run() {
		userPublicKeyManager = new UserPublicKeyManager();
        try {
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); //AKS: Stream associated with control socket used to communicate with server
            out = new PrintWriter(clientSocket.getOutputStream(), true);  //AKS: Stream associated with control socket used to communicate with server

            // Step 1: User Registration
            //String username = in.readLine();
            synchronized (users) {
                if (users.containsKey(username)) {
                    out.println("Username already taken. Disconnecting...");
                    clientSocket.close();
                    return;
                }
                currentUser = new User(username, clientSocket);
                users.put(username, currentUser); //AKS: Just, added this comment. User has just connected.  There is no connected user, who wants to chat at this point.

                // Send welcome message ONLY ONCE
                //out.println("Welcome, " + username + "! You are now online and idle.");

                // Broadcast user list update
                broadcastUserListUpdate(currentUser.getUsername() + " joined the chat.");
            }

            // Step 2: Listen for commands
            String command;
            while ((command = in.readLine()) != null) {
                command = command.trim();
                
				//System.out.println("current user name is: "+currentUser.getUsername() + ", current user is: "+currentUser.getConnectedUser()); //AKS: Added this statement for debugging.  You should have a valid connected user after acceptance of a connection.
                // Check if user is in chat mode
                if (currentUser.getConnectedUser()!=null) {
                    handleChatMessage(command);
                    continue;
                }

                // Existing command handling
                if (command.equalsIgnoreCase("list")) {
                    listOnlineUsers(out);
                } else if (command.startsWith("connect ")) {
                    handleConnectionRequest(command.substring(8).trim(), out);
                } else if (command.equalsIgnoreCase("accept")) {
                    handleConnectionAcceptance(out);
                } else if (command.equalsIgnoreCase("reject")) {
                    handleConnectionRejection(out);
                } else if (command.equalsIgnoreCase("quit")) {
                    break;
                } 
				else {
                    out.println("Invalid command. Available commands: list, connect <username>, accept, reject, quit");
                }
            }
        } catch (Exception e) {
            //System.err.println("Error handling user: " + e.getMessage());
        } finally {
            disconnectUser();
        }
    }

    private void handleConnectionRequest(String targetUsername, PrintWriter requesterOut) {
        synchronized (users) {
            User targetUser = users.get(targetUsername);
            if (targetUser == null) {
                requesterOut.println("User " + targetUsername + " does not exist.");
                return;
            }
            if (targetUser.getStatus() == Status.BUSY) {
                requesterOut.println("User " + targetUsername + " is currently busy.");
                return;
            }

            try {
                // Update status of requester
                currentUser.setStatus(Status.CONNECTING);
                // Set the pending connection target
                currentUser.setPendingConnectionTarget(targetUser);

                // Prepare connection request notification
                PrintWriter targetOut = new PrintWriter(targetUser.getSocket().getOutputStream(), true);

                // Set target user's status to BUSY
                targetUser.setStatus(Status.BUSY);

                // Send connection request to target user
                targetOut.println("CONNECTION_REQUEST:" + currentUser.getUsername());

                // Notify requester
                requesterOut.println("Waiting for " + targetUsername + "'s response...");

            } catch (IOException e) {
                requesterOut.println("Error sending connection request.");
            }
        }
    }


    private void handleConnectionAcceptance(PrintWriter out) {
        synchronized (users) {
            //User requesterUser = null;
            for (User user : users.values()) {
                if (user.getStatus() == Status.CONNECTING && 
                    user.getPendingConnectionTarget() != null && 
                    user.getPendingConnectionTarget().equals(currentUser)) {
                    requesterUser = user;
                    break;
                }
            }

            if (requesterUser == null) {
                out.println("No pending connection request.");
                return;
            }

            try {
                PrintWriter requesterOut = new PrintWriter(requesterUser.getSocket().getOutputStream(), true);

                // Update statuses for both users to 'BUSY'
                currentUser.setStatus(Status.BUSY);
                requesterUser.setStatus(Status.BUSY);

                // Clear the pending connection state
                requesterUser.clearPendingConnection();				
				
				PublicKey currentUserPublicKey = userPublicKeyManager.loadUserPublicKey(currentUser.getUsername());
				PublicKey targetUserPublicKey = userPublicKeyManager.loadUserPublicKey(requesterUser.getUsername());
				
				byte[] pk1= currentUserPublicKey.getEncoded();
				byte[] pk2= targetUserPublicKey.getEncoded();
				byte[] sessionKey= RSAUtils.generateSessionKey(pk1,pk2);
				String encoded = java.util.Base64.getEncoder().encodeToString(sessionKey);
				
                // Notify both users about the connection acceptance
                //out.println("You accepted the connection with " + requesterUser.getUsername()+". Your session key is: "+encoded);
                //requesterOut.println(currentUser.getUsername() + " accepted your connection request. Your session key is: "+encoded);
				requesterUser.setConnectedUser(currentUser); //AKS: Added this statement. Initiator of the chat is now connected to current user. <---  BUG FIX
 				currentUser.setConnectedUser(requesterUser); //AKS: Added this statement. Accepter of the chat i.e is the current user is connected to requesterUser. <---  BUG FIX
                // Start peer-to-peer chat in a new thread
                PeerChat peerChat = new PeerChat(currentUser, requesterUser);
                new Thread(peerChat).start();
				
                // Broadcast the connection status to all users
                broadcastUserListUpdate(currentUser.getUsername() + " and " + requesterUser.getUsername() + " are now connected. Your session key is: "+encoded);

            } catch (Exception e) {
                out.println("Error processing connection acceptance.");
                // Reset status if there's an error
                currentUser.setStatus(Status.IDLE);
                requesterUser.setStatus(Status.IDLE);
            }
        }
    }
    private void handleChatMessage(String message) {
        try {
            // Get the connected user
			
			//System.out.println("key: " + message); //AKS: Added
            User connectedUser = currentUser.getConnectedUser();
            
            // Check for quit command
            if (message.equalsIgnoreCase("quit")) { //AKS: replaced "/quit" by "quit"
                // Notify both users
                PrintWriter currentOut = new PrintWriter(currentUser.getSocket().getOutputStream(), true);
                PrintWriter connectedOut = new PrintWriter(connectedUser.getSocket().getOutputStream(), true);
                
                currentOut.println("You have left the chat.");
                connectedOut.println(currentUser.getUsername() + " has left the chat.");
                
                // Reset users' statuses and connected users
                currentUser.setStatus(Status.IDLE);
                connectedUser.setStatus(Status.IDLE);
                currentUser.setConnectedUser(null);
                connectedUser.setConnectedUser(null);
                
                return;
            }
            
            // Send message to connected user
            PrintWriter connectedOut = new PrintWriter(connectedUser.getSocket().getOutputStream(), true);
            //connectedOut.println(currentUser.getUsername() + ": " + message); //AKS:Commented as prefixing the message with username messes with the encryption/decryption
			//System.out.println("key : " + message);
			connectedOut.println(message); //AKS:removing user prefix, as prefixing the message with username messes with the encryption/decryption
        } catch (IOException e) {
            System.err.println("Error sending chat message: " + e.getMessage());
        }
    }

    private void handleConnectionRejection(PrintWriter out) {
        synchronized (users) {
            // Verify a pending connection exists
            if (pendingConnectionUser == null) {
                out.println("No pending connection request.");
                return;
            }

            try {
                // Get the requester's output stream
                PrintWriter requesterOut = new PrintWriter(pendingConnectionUser.getSocket().getOutputStream(), true);

                // Reset statuses
                currentUser.setStatus(Status.IDLE);
                pendingConnectionUser.setStatus(Status.IDLE);

                // Notify both users
                out.println("You rejected the connection with " + pendingConnectionUser.getUsername());
                requesterOut.println(currentUser.getUsername() + " rejected your connection request.");

                // Broadcast user status update (with specific user information)
                broadcastUserListUpdate(currentUser.getUsername() + " rejected " + pendingConnectionUser.getUsername() + "'s connection request.");

                // Clear pending connection
                pendingConnectionUser = null;
            } catch (IOException e) {
                out.println("Error processing connection rejection.");
            }
        }
    }

    private void listOnlineUsers(PrintWriter out) {
        out.println("Online users:");
        synchronized (users) {
            users.forEach((username, user) -> {
                if (!username.equals(currentUser.getUsername())) {
                    out.println(username + " (" + user.getStatus().toString().toLowerCase() + ")");
                }
            });
        }
        out.println("User list updated.");
    }

    private void broadcastUserListUpdate(String message) {
        synchronized (users) {
            users.forEach((username, user) -> {
                try {
                    PrintWriter userOut = new PrintWriter(user.getSocket().getOutputStream(), true);
                    userOut.println(message);
                } catch (IOException e) {
                    System.err.println("Error broadcasting update to " + username + ": " + e.getMessage());
                }
            });
        }
    }

    private void disconnectUser() {
        if (currentUser != null) {
            synchronized (users) {
                users.remove(currentUser.getUsername());
                broadcastUserListUpdate(currentUser.getUsername() + " has left the chat.");
            }
            System.out.println("User " + currentUser.getUsername() + " disconnected.");

            try {
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error closing client socket: " + e.getMessage());
            }
        }
    }
}
                