import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.security.PublicKey;
import java.util.concurrent.atomic.AtomicLong;

@SuppressWarnings("resource")
public class ServidorGrande {

    
    
    public static void main(String[] args) throws Exception{
        int port = 3400;

        // Generar el par de llaves
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        byte[] publicKeyBytes = publicKey.getEncoded();
        Files.write(Paths.get("publicKey.key"), publicKeyBytes);
        System.out.println("Public key saved to publicKey.key");

        // POOL DE SERVIDORES
        ServerSocket serverSocket = new ServerSocket(port);
        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(new Servidor(clientSocket, pair)).start();
        }
                
        
    }
    
}
