import javax.crypto.KeyGenerator;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class Main {
    private static int PORT_1 = 10022;
    private static int PORT_2 = 10023;
    private static int PORT_3 = 10024;

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
    }
}
