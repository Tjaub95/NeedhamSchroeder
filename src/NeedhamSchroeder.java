import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;

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

    void sendUnencryptedMessage(String message, Socket messageSocket) {
        try {
            DataOutputStream sendMess = new DataOutputStream(messageSocket.getOutputStream());
            System.out.printf("Unencrypted Message is: %s\n", message);
            sendMess.writeBytes(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    void sendEncryptedMessage(String message, Socket messageSocket, Key key) {
        try {
            DataOutputStream sendMess = new DataOutputStream(messageSocket.getOutputStream());
            String encryptedMess = encrypt(message, key);
            System.out.printf("Encrypted Message is: %s\n", encryptedMess);
            sendMess.writeBytes(encryptedMess + "\r");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    String receiveUnencryptedMessage(Socket messageSocket) {
        String receivedMessage = "";
        try {
            BufferedReader readInServerResp = new BufferedReader(new InputStreamReader(messageSocket.getInputStream()));
            receivedMessage = readInServerResp.readLine();
            if (receivedMessage.isEmpty()) {
                receivedMessage = readInServerResp.readLine();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.printf("Received message: %s\n", receivedMessage);
        return receivedMessage;
    }

    String receiveEncryptedMessage(Socket messageSocket, Key key) {
        String receivedMessage = receiveUnencryptedMessage(messageSocket);
        return decryptWithAnotherKey(receivedMessage, key);
    }

    String receiveAllMessages(Socket messageSocket) {
        StringBuilder receivedMessages = new StringBuilder();
        try {
            BufferedReader readInFromServer = new BufferedReader(new InputStreamReader(messageSocket.getInputStream()));
            while(true) {
                receivedMessages.append(readInFromServer.readLine());
                if (readInFromServer.ready()) {
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.printf("Received messages: %s\n", receivedMessages);
        return receivedMessages.toString();
    }

    String encrypt(String message, Key key) {
        String encryptedMess = "";
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encipheredBytes = cipher.doFinal(message.getBytes());
            encryptedMess = new BASE64Encoder().encode(encipheredBytes);
            System.out.printf("Encrypted message is: %s\n", encryptedMess);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedMess;
    }

    String decryptWithMyKey(String message) {
        String decryptedMessage = "";
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, getToken());
            byte[] decryptedCipher = cipher.doFinal(new BASE64Decoder().decodeBuffer(message));
            decryptedMessage = new String(decryptedCipher);
            System.out.printf("Decrypted message is: %s\n", decryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedMessage;
    }

    String decryptWithAnotherKey(String message, Key key) {
        String decryptedMessage = "";
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedCipher = cipher.doFinal(new BASE64Decoder().decodeBuffer(message));
            decryptedMessage = new String(decryptedCipher);
            System.out.printf("Decrypted message is: %s\n", decryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedMessage;
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
