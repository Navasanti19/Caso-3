import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class ServidorMonothread {
	
	private static final int PUERTO = 3400;
	
	public static void main(String[] args) throws IOException{
		
		ServerSocket ss = null;
		boolean continuar = true;
		System.out.println("Comienza servidor");
		
		try {
			ss = new ServerSocket(PUERTO);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}
		
		while(continuar) {
			Socket socket = ss.accept();
			
			try {
				PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				
				System.out.println(lector.readLine());
				escritor.println("Hola cliente");
				
				socket.close();
				escritor.close();
				lector.close();
			}catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
}
