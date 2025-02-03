package client;

import common.MessageUtils;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;

public class ClientInputHandler implements Runnable {
    private final PrintWriter outToServerControl;
    private final BufferedReader inFromUser;
    private boolean awaitingResponse = false;  // Flag to control when awaiting response
	private SecretKey encKey=null; //AKS: Will be set from NotificationListener after it receives the session master from the server.
	
	public void setEncryptionKey(SecretKey encKey)
	{
		this.encKey = encKey;
	}

    public ClientInputHandler(PrintWriter outToServerControl, BufferedReader inFromUser) {
        this.outToServerControl = outToServerControl;
        this.inFromUser = inFromUser;
		
    }

    @Override
    public void run() {
        try {
            String userInput;
            while ((userInput = inFromUser.readLine()) != null) {
                if (awaitingResponse) {
                    // Handle only 'accept' or 'reject' when waiting for response
                    if (userInput.trim().equalsIgnoreCase("accept")) {
                        outToServerControl.println("accept");  // Send accept to the server
                        awaitingResponse = false;  // Reset awaiting response flag
                    } else if (userInput.trim().equalsIgnoreCase("reject")) {
                        outToServerControl.println("reject");  // Send reject to the server
                        awaitingResponse = false;  // Reset awaiting response flag
                    } 
					
					else {
                        System.out.println("Invalid command. Only 'accept' or 'reject' are allowed.");
                    }
                } else {
                    // Normal commands are allowed when not awaiting response
                    if (userInput.trim().equalsIgnoreCase("quit")) {
                        System.out.println("Disconnecting from the server...");
                        outToServerControl.println("quit");
                        break; //AKS: Allowing the handler thread to terminate.
                    } else if (userInput.trim().equalsIgnoreCase("list")) {
                        outToServerControl.println("list");
                    } else if (userInput.startsWith("connect ")) {
                        outToServerControl.println(userInput);
                    }else if(awaitingResponse==false){ //chat is on and this side sends information that is read from System.in
						//If sessionKey is not empty, then you need to encrypt and send.
						if (encKey != null) //AKS: Added the entire IF, else block.
						{
							String cipherText = MessageUtils.encrypt(userInput, encKey);
							//System.out.println("You: " + userInput);
				            //System.out.println("EncryptionKey: " + encKey );
							//System.out.println("Encrypted Message: " + cipherText );
							outToServerControl.println(cipherText);
						}
						else
						{
							//No encryption key.  Just send the message ASIS
							System.out.println("Message not encrypted as there is no encKey available.");
							System.out.println("Plain Text message being sent: " + userInput);
							outToServerControl.println(userInput);
						}
					} 
					else {
                        System.out.println("Invalid command. Try again.");
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error reading input: " + e.getMessage());
        }
    }

    // Method to set awaiting response flag when a connection request is received
    public void setAwaitingResponse(boolean awaitingResponse) {
        this.awaitingResponse = awaitingResponse;
    }
}
