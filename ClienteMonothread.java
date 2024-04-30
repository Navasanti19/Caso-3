import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClienteMonothread {
	
	public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";
	
	public static void main(String[] args) throws IOException {
		
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		
		System.out.println("Comienza cliente");
		
		try {
			socket = new Socket(SERVIDOR, PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		
		escritor.println("Hola servidor");
		System.out.println(lector.readLine());
		
		socket.close();
		escritor.close();
		lector.close();
	}
}
