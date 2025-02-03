package server;

import java.net.Socket;

public class User {
    private final String username;
    private final Socket socket;
    private Status status;
    private User pendingConnectionTarget;
    private User connectedUser; // New field

    public User(String username, Socket socket) {
        this.username = username;
        this.socket = socket;
        this.status = Status.IDLE;
    }

    public String getUsername() {
        return username;
    }

    public Socket getSocket() {
        return socket;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public User getPendingConnectionTarget() {
        return this.pendingConnectionTarget;
    }

    public void setPendingConnectionTarget(User target) {
        this.pendingConnectionTarget = target;
    }

    public void clearPendingConnection() {
        this.pendingConnectionTarget = null;
    }
    public User getConnectedUser() {
        return connectedUser;
    }

    public void setConnectedUser(User connectedUser) {
        this.connectedUser = connectedUser;
    }
}