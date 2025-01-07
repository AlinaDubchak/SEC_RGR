import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
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
                PublicKey serverPublicKey = readPublicKeyFromFile();

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

                // Генерація ключа сеансу
                byte[] sessionKey = KeyUtils.generateSessionKey(clientHello, serverHello, premasterSecret);
                System.out.println("[Client] Generated session key: " + Base64.getEncoder().encodeToString(sessionKey));

                // Отримання зашифрованого повідомлення "готовий" від сервера
                String encryptedReadyMessageBase64 = in.readUTF();
                byte[] encryptedReadyMessage = Base64.getDecoder().decode(encryptedReadyMessageBase64);
                cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                byte[] decryptedReadyMessage = cipher.doFinal(encryptedReadyMessage);
                String readyMessage = new String(decryptedReadyMessage);
                System.out.println("[Client] Decrypted 'ready' message from server: " + readyMessage);

                // Відправка підтвердження готовності серверу
                String readyMessageClient = "Think only of the past as its remembrance gives you pleasure.";
                cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                byte[] encryptedReadyMessageClient = cipher.doFinal(readyMessageClient.getBytes());
                out.writeUTF(Base64.getEncoder().encodeToString(encryptedReadyMessageClient));
                System.out.println("[Client] Sent encrypted 'ready' message to server.");

                // Синхронізація з сервером
                barrier.await();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }

    // Зчитування публічного ключа з файлу
    private PublicKey readPublicKeyFromFile() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("server_public_key.txt"));
            String line;
            StringBuilder keyBuilder = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                if (!line.startsWith("--") && !line.endsWith("--")) {
                    keyBuilder.append(line);
                }
            }
            byte[] publicKeyBytes = Base64.getDecoder().decode(keyBuilder.toString());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }
}
