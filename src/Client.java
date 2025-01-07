import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import java.util.concurrent.*;

public class Client {
    private final String host;
    private final int port;
    private final CyclicBarrier barrier;

    public Client(String host, int port, CyclicBarrier barrier) {
        this.host = host;
        this.port = port;
        this.barrier = barrier;
    }

    public void start() {
        new Thread(() -> {
            try (Socket socket = new Socket(host, port);
                 DataInputStream in = new DataInputStream(socket.getInputStream());
                 DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

                // Відправка "hello" на сервер
                String clientHello = "Hello from client: " + Math.random();
                out.writeUTF(clientHello);
                System.out.println("[Client] Sent to server: " + clientHello);

                // Отримання server "hello" та публічного ключа
                String serverHello = in.readUTF();
                String serverPublicKeyBase64 = in.readUTF();

                System.out.println("[Client] Received from server: " + serverHello);
                System.out.println("[Client] Server public key: " + serverPublicKeyBase64);

                // Відновлення публічного ключа сервера
                byte[] serverPublicKeyBytes = Base64.getDecoder().decode(serverPublicKeyBase64);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));

                // Генерація та шифрування premaster секрету
                String premasterSecret = "PremasterSecret: " + Math.random();
                System.out.println("[Client] Premaster secret (before encryption): " + premasterSecret);
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
                byte[] encryptedPremaster = cipher.doFinal(premasterSecret.getBytes());
                String encryptedPremasterBase64 = Base64.getEncoder().encodeToString(encryptedPremaster);

                // Відправка зашифрованого premaster на сервер
                out.writeUTF(encryptedPremasterBase64);
                System.out.println("[Client] Sent encrypted premaster secret to server.");

                // Синхронізація з сервером
                barrier.await();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }
}
