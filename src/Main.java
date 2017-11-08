import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.ServerSocket;

public class Main {

    public static void main(String[] args) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);

            SecretKey aliceSecKey = keyGen.generateKey();
            SecretKey bobSecKey = keyGen.generateKey();

            Alice alice = new Alice(aliceSecKey, 1002, "Alice", new ServerSocket(1002));
            Bob bob = new Bob(bobSecKey, 1001, "Bob", new ServerSocket(1001));
            Cathy cathy = new Cathy(1000, "Cathy", new ServerSocket(1000));

            cathy.getSecretKeyHashMap().put(alice.getNsUserName(), aliceSecKey);
            cathy.getSecretKeyHashMap().put(bob.getNsUserName(), bobSecKey);

            new Thread(alice).start();
            new Thread(bob).start();
            new Thread(cathy).start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
