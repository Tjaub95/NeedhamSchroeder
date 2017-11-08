import javax.crypto.SecretKey;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.Random;

public class Bob extends NeedhamSchroeder {

    public Bob(SecretKey token, int portNum, String nsUserName, ServerSocket socket) {
        super(token, portNum, nsUserName, socket);
    }

    @Override
    public void run() {
        System.out.printf("%s has started\n", this.getNsUserName());
        try {
            Socket sending = getSocket().accept();

            String receivedMessage = receiveUnencryptedMessage(sending);

            String decryptedMessage = decryptWithMyKey(receivedMessage);

            String[] decryptedFields = decryptedMessage.split(NeedhamSchroeder.MESS_FLAG);
            Key key = sessionKey(decryptedFields[1]);

            Random rand = new Random();
            String nonce = String.valueOf(rand.nextInt());

            nonce = encrypt(nonce, key);

            sendUnencryptedMessage(nonce + "\r", sending);

            String receivedNonce = receiveUnencryptedMessage(sending);

            String decryptedNonce = decryptWithAnotherKey(receivedNonce, key);

            if (Integer.parseInt(nonce) - Integer.parseInt(decryptedNonce) == 1) {
                System.out.println("Needham Schroeder Key Exchange Successful");

                for (int i = 1; i < 4; i++) {
                    receiveEncryptedMessage(sending, key);
                    sendEncryptedMessage(String.format("%s is sending message %d to Alice.", this.getNsUserName(), i), sending, key);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
