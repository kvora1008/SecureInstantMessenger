package server;

import java.io.*;
import java.net.Socket;
import java.util.Date;

public class PeerChat implements Runnable {
    private final User user1;
    private final User user2;
    private boolean isActive;

    public PeerChat(User user1, User user2) {
        this.user1 = user1;
        this.user2 = user2;
        this.isActive = true;
    }

    @Override
    public void run() {
        try {
            // Notify users about connection
            sendMessageToUser(user1, "You are now connected to " + user2.getUsername());
            sendMessageToUser(user2, "You are now connected to " + user1.getUsername());
			String connectedMsg="Chat connection created between "+user1.getUsername()+" and "+user2.getUsername()+".";
			logToActivityFile(connectedMsg);

            // Setup input streams
            BufferedReader in1 = new BufferedReader(new InputStreamReader(user1.getSocket().getInputStream()));
            BufferedReader in2 = new BufferedReader(new InputStreamReader(user2.getSocket().getInputStream()));

            // Setup output streams
            PrintWriter out1 = new PrintWriter(user1.getSocket().getOutputStream(), true);
            PrintWriter out2 = new PrintWriter(user2.getSocket().getOutputStream(), true);

            // Flag to help manage chat
            out1.println("CHAT_STARTED");
            out2.println("CHAT_STARTED");

            // Threads to handle incoming messages
            Thread user1Thread = createMessageThread(in1, out2, user1, user2);
            Thread user2Thread = createMessageThread(in2, out1, user2, user1);

            user1Thread.start();
            user2Thread.start();

            // Wait for threads to complete
            user1Thread.join();
            user2Thread.join();
			
			String closeMsg="End of chat between "+user1.getUsername()+" and "+user2.getUsername()+".";
			logToActivityFile(closeMsg);

        } catch (IOException | InterruptedException e) {
            System.err.println("Error in peer chat: " + e.getMessage());
        } finally {
            // Reset user statuses
            user1.setStatus(Status.IDLE);
            user2.setStatus(Status.IDLE);
            isActive = false;
        }
    }

    private Thread createMessageThread(BufferedReader in, 
                                       PrintWriter out, 
                                       User sender, 
                                       User receiver) {
        return new Thread(() -> {
            try {
                String message;
                while ((message = in.readLine()) != null) {
                    // Check for quit command
                    if (message.equalsIgnoreCase("quit")) {
                        out.println(sender.getUsername() + " has left the chat.");
                        break;
                    }

                    // Forward messages
                    //out.println(sender.getUsername() + ": " + message); //AKS: Commented this line as prefixing with username interferes with both encryption/decryption
					out.println(message); //AKS: Don't prefix with username as it screws up the encryption/decryption;
                }
            } catch (IOException e) {
				//System.err.println("Error in message thread: " + e.getMessage());
            }
        });
    }

    private void sendMessageToUser(User user, String message) throws IOException {
        PrintWriter out = new PrintWriter(user.getSocket().getOutputStream(), true);
        out.println(message);
    }

    public boolean isActive() {
        return isActive;
    }
	
	private static void logToActivityFile(String message) {
        try (FileWriter fw = new FileWriter("activity.log", true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            out.println("[" + new Date() + "] " + message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}