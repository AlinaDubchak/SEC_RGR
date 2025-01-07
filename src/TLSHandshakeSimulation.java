import java.util.concurrent.*;

public class TLSHandshakeSimulation {
    public static void main(String[] args) {
        int port = 3000;
        ExecutorService executor = Executors.newFixedThreadPool(2);

        CyclicBarrier barrier = new CyclicBarrier(2, () -> {
            System.out.println("Handshake complete. Both client and server are ready.");
        });

        Server server = new Server(port, barrier);
        executor.submit(() -> server.start());

        Client client = new Client("localhost", port, barrier);
        executor.submit(() -> client.start());
    }
}
