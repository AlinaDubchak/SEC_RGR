import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
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
                System.out.println("Server started and waiting for client...");

                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("Client connected.");

                    try (DataInputStream in = new DataInputStream(clientSocket.getInputStream());
                         DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream())) {

                        // Отримати "hello" від клієнта
                        String clientHello = in.readUTF();
                        System.out.println("Received from client: " + clientHello);

                        // Генерація server "hello" та пари ключів
                        String serverHello = "Hello from server: " + Math.random();
                        KeyPair keyPair = KeyUtils.generateKeyPair();
                        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

                        // Відправка server "hello" та публічного ключа клієнту
                        out.writeUTF(serverHello);
                        out.writeUTF(publicKey);
                        System.out.println("Sent to client: " + serverHello + " and public key.");

                        // Синхронізація з клієнтом
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
