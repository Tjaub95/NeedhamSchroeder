import javax.crypto.SecretKey;
import java.net.ServerSocket;

public abstract class NeedhamSchroeder implements Runnable {
    private SecretKey token;
    private int portNum;
    private String nsUserName;
    private ServerSocket socket;

    NeedhamSchroeder(SecretKey token, int portNum, String nsUserName, ServerSocket socket) {
        this.token = token;
        this.portNum = portNum;
        this.nsUserName = nsUserName;
        this.socket = socket;
    }

    /**
     * Getters and Setters
     */
    public SecretKey getToken() {
        return token;
    }

    public void setToken(SecretKey token) {
        this.token = token;
    }

    public int getPortNum() {
        return portNum;
    }

    public void setPortNum(int portNum) {
        this.portNum = portNum;
    }

    public String getNsUserName() {
        return nsUserName;
    }

    public void setNsUserName(String nsUserName) {
        this.nsUserName = nsUserName;
    }

    public ServerSocket getSocket() {
        return socket;
    }

    public void setSocket(ServerSocket socket) {
        this.socket = socket;
    }
}
