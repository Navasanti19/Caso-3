import java.util.Scanner;
import java.util.concurrent.atomic.AtomicLong;

public class ClienteGrande {

    static AtomicLong timeVerifySignature = new AtomicLong(0);
    static AtomicLong timeCalculateGy = new AtomicLong(0);
    static AtomicLong timeEncryptQuery = new AtomicLong(0);
    static AtomicLong timeGenerateAuthCode = new AtomicLong(0);
    
    static AtomicLong timeGenerateSignature = new AtomicLong(0);
    static AtomicLong timeDecryptQuery = new AtomicLong(0);
    static AtomicLong timeVerifyAuthCode = new AtomicLong(0);

    public static void main(String[] args) {

        
        
        // Pedir número de clientes
        System.out.println("Número de clientes a crear: ");
        Scanner scanner = new Scanner(System.in);
        int numberOfClients = scanner.nextInt();
        scanner.close();

        Thread[] clientThreads = new Thread[numberOfClients];


        for (int i = 0; i < numberOfClients; i++) {
            clientThreads[i] = new Thread(new Cliente("localhost", 3400, i));
            clientThreads[i].start();
        }

        for (int i = 0; i < numberOfClients; i++) {
            try {
                clientThreads[i].join(); // Espera a que el hilo i termine
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // Restaurar el estado de interrupción
                System.out.println("Hilo interrumpido: " + e.getMessage());
            }
        }

        System.out.println("Total time to verify signature: " + String.format("%.2f", timeVerifySignature.get() / 1_000_000.0) + " ms");
        System.out.println("Total time to calculate Gy: " + String.format("%.2f", timeCalculateGy.get() / 1_000_000.0) + " ms");
        System.out.println("Total time to encrypt query: " + String.format("%.2f", timeEncryptQuery.get() / 1_000_000.0) + " ms");
        System.out.println("Total time to generate auth code: " + String.format("%.2f", timeGenerateAuthCode.get() / 1_000_000.0) + " ms");
        
        System.out.println("Total time to generate signature: " + String.format("%.2f", timeGenerateSignature.get() / 1_000_000.0) + " ms");
        System.out.println("Total time to decrypt query: " + String.format("%.2f", timeDecryptQuery.get() / 1_000_000.0) + " ms");
        System.out.println("Total time to verify auth code: " + String.format("%.2f", timeVerifyAuthCode.get() / 1_000_000.0) + " ms");
    }
}