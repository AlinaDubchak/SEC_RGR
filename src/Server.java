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

                        // Запис публічного ключа у файл
                        writePublicKeyToFile(publicKeyBase64);

                        // Виведення публічного ключа у консоль у вказаному форматі
                        System.out.println("[Server] Public Key (formatted): ");
                        printFormattedPublicKey(publicKeyBase64);

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
                        String readyMessage = "I could easily forgive his pride, if he had not mortified mine";
                        cipher = Cipher.getInstance("AES");
                        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                        byte[] encryptedReadyMessage = cipher.doFinal(readyMessage.getBytes());
                        out.writeUTF(Base64.getEncoder().encodeToString(encryptedReadyMessage));
                        System.out.println("[Server] Sent encrypted 'ready' message to client.");

                        // Отримання зашифрованого повідомлення "готовий" від клієнту
                        String encryptedReadyMessageBase64 = in.readUTF();
                        byte[] encryptedReadyMessageServer = Base64.getDecoder().decode(encryptedReadyMessageBase64);
                        cipher = Cipher.getInstance("AES");
                        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                        byte[] decryptedReadyMessage = cipher.doFinal(encryptedReadyMessageServer);
                        String readyMessageServer = new String(decryptedReadyMessage);
                        System.out.println("[Server] Decrypted 'ready' message from client: " + readyMessageServer);

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

    // Запис публічного ключа у файл
    private void writePublicKeyToFile(String publicKeyBase64) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("server_public_key.txt"))) {
            writer.write("--Begin public key\n");
            writer.write(publicKeyBase64);
            writer.write("\n--End public key");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Виведення публічного ключа у форматі
    private void printFormattedPublicKey(String publicKeyBase64) {
        System.out.println("--Begin public key");
        System.out.println(publicKeyBase64);
        System.out.println("--End public key");
    }
}
