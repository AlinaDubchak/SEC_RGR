import java.security.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyUtils {
    // Метод для генерації пари RSA ключів
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    // Метод для генерації ключа сеансу (AES)
    public static byte[] generateSessionKey(String clientRandom, String serverRandom, String premasterSecret) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        String combined = clientRandom + serverRandom + premasterSecret;
        return sha256.digest(combined.getBytes());
    }
}
