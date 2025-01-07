import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.concurrent.CyclicBarrier;

public class Server {
    private final int port;
    private final CyclicBarrier barrier;

    public Server(int port, CyclicBarrier barrier) {
        this.port = port;
        this.barrier = barrier;
    }

    public void start() {
        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                System.out.println("[Server] Server started and waiting for client...");

                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("[Server] Client connected.");

                    try (DataInputStream in = new DataInputStream(clientSocket.getInputStream());
                         DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream())) {

                        // Отримати "hello" від клієнта
                        String clientHello = in.readUTF();
                        System.out.println("[Server] Received from client: " + clientHello);

                        // Генерація server "hello" та пари ключів
                        String serverHello = "Hello from server: " + Math.random();
                        KeyPair keyPair = KeyUtils.generateKeyPair();
                        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

                        // Відправка server "hello" та публічного ключа клієнту
                        out.writeUTF(serverHello);
                        out.writeUTF(publicKeyBase64);
                        System.out.println("[Server] Sent to client: " + serverHello + " and public key.");

                        // Отримання зашифрованого premaster секрету
                        String encryptedPremasterBase64 = in.readUTF();
                        byte[] encryptedPremaster = Base64.getDecoder().decode(encryptedPremasterBase64);
                        System.out.println("[Server] Encrypted premaster secret received: " + encryptedPremasterBase64);

                        // Розшифрування premaster секрету
                        Cipher cipher = Cipher.getInstance("RSA");
                        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                        byte[] premasterBytes = cipher.doFinal(encryptedPremaster);
                        String premasterSecret = new String(premasterBytes);
                        System.out.println("[Server] Decrypted premaster secret: " + premasterSecret);

                        // Генерація ключа сеансу
                        byte[] sessionKey = KeyUtils.generateSessionKey(clientHello, serverHello, premasterSecret);
                        System.out.println("[Server] Generated session key: " + Base64.getEncoder().encodeToString(sessionKey));

                        // Відправка повідомлення "готовий", зашифрованого сеансовим ключем
                        String readyMessage = "Ready from server";
                        cipher = Cipher.getInstance("AES");
                        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                        byte[] encryptedReadyMessage = cipher.doFinal(readyMessage.getBytes());
                        out.writeUTF(Base64.getEncoder().encodeToString(encryptedReadyMessage));
                        System.out.println("[Server] Sent encrypted 'ready' message to client.");

                        // Очікування синхронізації з клієнтом
                        barrier.await();

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();
    }
}
