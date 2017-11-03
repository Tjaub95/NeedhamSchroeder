import javax.crypto.SecretKey;
import java.net.ServerSocket;

public class Cathy extends NeedhamSchroeder {

    public Cathy(SecretKey token, int portNum, String nsUserName, ServerSocket socket) {
        super(token, portNum, nsUserName, socket);
    }

    @Override
    public void run() {

    }
}
