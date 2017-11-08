import javax.crypto.SecretKey;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.Random;

public class Alice extends NeedhamSchroeder {

    public Alice(SecretKey token, int portNum, String nsUserName, ServerSocket socket) {
        super(token, portNum, nsUserName, socket);
    }

    @Override
    public void run() {
        System.out.printf("%s has started\n", this.getNsUserName());

        try {
            Socket sendingSocket = new Socket("localhost", 1000);

            Random rand = new Random();
            String nonce = String.valueOf(rand.nextInt());

            String message = buildSentMessageWithFlag("Alice", "Bob", nonce);

            sendUnencryptedMessage(message, sendingSocket);

            String receivedMess = receiveAllMessagesNoEncryption(sendingSocket);

            String decryptedMess = decryptWithMyKey(receivedMess);

            sendingSocket.close();

            String[] decryptedFields = decryptedMess.split(NeedhamSchroeder.MESS_FLAG);

            Key key = sessionKey(decryptedFields[3]);

            sendingSocket = new Socket("localhost", 1001);

            sendUnencryptedMessage(decryptedFields[4] + '\r', sendingSocket);

            String receivedNonce = receiveEncryptedMessage(sendingSocket, key);

            String sentNonce = String.valueOf(Integer.parseInt(receivedNonce) - 1);

            sendUnencryptedMessage(encrypt(sentNonce, key) + "\r", sendingSocket);

            for (int i = 1; i < 4; i++) {
                sendEncryptedMessage(String.format("%s is sending a message %d to Bob.", this.getNsUserName(), i), sendingSocket, key);
                receiveEncryptedMessage(sendingSocket, key);
            }

            sendingSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
