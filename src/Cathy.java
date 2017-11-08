import sun.misc.BASE64Encoder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

public class Cathy extends NeedhamSchroeder {

    private HashMap<String, SecretKey> secretKeyHashMap = new HashMap<>();
    public Cathy(int portNum, String nsUserName, ServerSocket socket) {
        super(null, portNum, nsUserName, socket);
    }

    @Override
    public void run() {
        System.out.printf("%s has started\n\n", this.getNsUserName());
        try {
            Socket caSocket = getSocket().accept();

            String receivedMessage = receiveUnencryptedMessage(caSocket);

            String[] receivedSplit = receivedMessage.split(NeedhamSchroeder.MESS_FLAG);

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);

            String key = new BASE64Encoder().encode(keyGen.generateKey().getEncoded());

            String bobMess = buildMessageWithFlag(receivedSplit[0], key);

            bobMess = encrypt(bobMess, getSecretKeyHashMap().get(receivedSplit[1]));

            String resp = buildMessageWithFlag(receivedSplit[0], receivedSplit[1], receivedSplit[2], key, bobMess);

            String encryptedResp = encrypt(resp, secretKeyHashMap.get(receivedSplit[0]));

            sendUnencryptedMessage(encryptedResp + "<KILL_MESS>\r", caSocket);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public HashMap<String, SecretKey> getSecretKeyHashMap() {
        return secretKeyHashMap;
    }
}
