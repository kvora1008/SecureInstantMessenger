package client;

import common.MessageUtils;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Base64;

public class NotificationListener implements Runnable {
    private final BufferedReader serverIn;
    private final ClientInputHandler inputHandler;
	private byte[] sessionKey = new byte[16]; 
	private SecretKey encKey = null;
	
    public NotificationListener(BufferedReader serverIn, ClientInputHandler inputHandler) {
        this.serverIn = serverIn;
        this.inputHandler = inputHandler;
    }

    @Override
    public void run() {
        try {
            String serverMessage;
            while ((serverMessage = serverIn.readLine()) != null) {
                // Check for connection request with the specific prefix
                if (serverMessage.startsWith("CONNECTION_REQUEST:")) {
                    String requesterUsername = serverMessage.substring("CONNECTION_REQUEST:".length());
                    System.out.println("Connection request from " + requesterUsername + ". Type 'accept' or 'reject':");
                    
                    // Process the connection request through the input handler
                    inputHandler.setAwaitingResponse(true);
                } else if(serverMessage.contains("Your session key is")){
					//System.out.println("Received session key from server."+serverMessage);
					String prefix = "Your session key is: ";
					String sessionKeyEncoded = serverMessage.substring(serverMessage.indexOf(prefix) + prefix.length()).trim();
										
					byte[] decodedKey = Base64.getDecoder().decode(sessionKeyEncoded);
					System.arraycopy(decodedKey, 0, sessionKey, 0, decodedKey.length);
					encKey = MessageUtils.deriveKey(sessionKey); //AKS: Added
					inputHandler.setEncryptionKey(encKey); //AKS:Added
				} else if (serverMessage.startsWith("quit"))//AKS: Added quit handler
				{
					System.out.println("Peer client disconnected");
					break; //AKS: we are breaking out so that the listener thread will terminate.
				}					
				else { //AKS: This block handles the chat message routed from the server.
				//DO NOT REMOVE- this code block actually prints the chat messages received from server on console
                    // Print other server messages
					
					//If sessionKey is not empty, then you need to decrypt and print.  Else print as is
					//System.out.println("Derived Encryption Key : " + encKey); //AKS: Added
					
					if (encKey != null)//AKS: Added
					{
						//System.out.println("Encrypted Message : " + serverMessage);
						System.out.println(">>"+ MessageUtils.decrypt(serverMessage, encKey)+'\n');
					}
					else
					{
						System.out.println(serverMessage + '\n');
					}
                }
            }
        } catch (Exception e) {
            System.err.println("Your session has ended. Exit manually and reconnect.");
        }
    }
}
