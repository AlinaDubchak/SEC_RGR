import java.io.*;
import java.net.*;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;

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
                System.out.println("Sent to server: " + clientHello);

                // Отримання server "hello" та публічного ключа
                String serverHello = in.readUTF();
                String serverPublicKey = in.readUTF();

                System.out.println("Received from server: " + serverHello);
                System.out.println("Server public key: " + serverPublicKey);

                // Синхронізація з сервером
                barrier.await();

            } catch (IOException | InterruptedException | BrokenBarrierException e) {
                e.printStackTrace();
            }
        }).start();
    }
}
