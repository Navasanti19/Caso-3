import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

public class Servidor extends Thread {

	private Socket clientSocket;
	PrintWriter escritor = null;
	BufferedReader lector = null;
	KeyPair pair = null;
	PrivateKey privateKey = null;
	PublicKey publicKey = null;

	
	public Servidor(Socket socket, KeyPair pair) {
		this.clientSocket = socket;
		this.pair = pair;
		this.privateKey = pair.getPrivate();
		this.publicKey = pair.getPublic();

	}

	@SuppressWarnings("unused")
	public void run() {

		BigInteger gxy = null;

		System.out.println("Comienza servidor");

		try {

			// --------------- INICIAR LA CONEXIÓN ---------------

			escritor = new PrintWriter(clientSocket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			privateKey = pair.getPrivate();
			publicKey = pair.getPublic();

			// ------------------ PASO 2 ------------------------------

			System.out.println("PASO 2: FIRMAR MENSAJE");
			Long startTime = System.nanoTime();
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            String mensaje = lector.readLine();
            byte[] messageBytes = mensaje.getBytes();

			signature.update(messageBytes);
            byte[] digitalSignature = signature.sign();
			String encodedMessage = Base64.getEncoder().encodeToString(digitalSignature);
			Long endTime = System.nanoTime();
			ClienteGrande.timeGenerateSignature.addAndGet(endTime - startTime);
			
			// ------------------ PASO 3 ------------------------------
			
			System.out.println("PASO 3: ENVIAR MENSAJE FIRMADO");
			escritor.println(encodedMessage);

			// ------------------ PASO 6 ------------------------------

			String respuesta5 = lector.readLine();
			if (respuesta5.equals("ERROR")) {
				return;
			}

			System.out.println("PASO 6: GENERAR P, G, GX, iv");
			
			BigInteger g = BigInteger.valueOf(2);
			
			String pHex = new String(Files.readAllBytes(Paths.get("P.txt"))).trim(); 
			BigInteger p = new BigInteger(pHex, 16);
			
			
			SecureRandom random = new SecureRandom();
			BigInteger x = new BigInteger(1024 - 2, random);
			BigInteger gx = g.modPow(x, p);
			
			byte[] iv = new byte[16];
			new SecureRandom().nextBytes(iv);
			
			String pBase64 = Base64.getEncoder().encodeToString(p.toByteArray());
			String gxBase64 = Base64.getEncoder().encodeToString(gx.toByteArray());
			String ivBase64 = Base64.getEncoder().encodeToString(iv);
			
			String datos = pBase64 + "|" + g + "|" + gxBase64;

			// ------------------ PASO 7 ------------------------------
			
			System.out.println("PASO 7: ENVIAR P, G, GX, iv y FIRMAR");
			escritor.println(pBase64);
			escritor.println("2"); // G es 2
			escritor.println(gxBase64);
			escritor.println(ivBase64);
			escritor.println(datos);

			signature.update(datos.getBytes());
			byte[] firma = signature.sign();

			encodedMessage = Base64.getEncoder().encodeToString(firma);
			escritor.println(encodedMessage);

			// ------------------ PASO 11B ------------------------------

			System.out.println("PASO 11b: CALCULAR LLAVES");

			String respuesta9 = lector.readLine();
			if (respuesta9.equals("ERROR")) {
				return;
			}

			String gyBase64 = lector.readLine();
			byte[] gyBytes = Base64.getDecoder().decode(gyBase64);
			BigInteger gy = new BigInteger(gyBytes);

			gxy = gy.modPow(x, p);

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] contextoBytes = "K_AB1".getBytes();
			md.update(contextoBytes);
			byte[] sharedSecret = gxy.toByteArray();
			byte[] claveDerivada = md.digest(sharedSecret);
			SecretKey kAB1 = new SecretKeySpec(claveDerivada, "AES");

			md = MessageDigest.getInstance("SHA-256");
			contextoBytes = "K_AB2".getBytes();
			md.update(contextoBytes);
			claveDerivada = md.digest(sharedSecret);
			SecretKey kAB2 = new SecretKeySpec(claveDerivada, "HmacSHA256");
			
			// ------------------ PASO 12 ------------------------------

			System.out.println("PASO 12: CONTINUAR");
			escritor.println("CONTINUAR");

			// ------------------ PASO 15 ------------------------------
			
			System.out.println("PASO 15: VERIFICAR LOGIN Y CONTRASEÑA");

			String loginEsperado = "s.navarretev";
			String passwordEsperado = "C0ntr4s3n4";

			String loginRecibido = lector.readLine();
			String passwordRecibido = lector.readLine();

			Cipher descifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
			byte[] ivBytes = Base64.getDecoder().decode(ivBase64);
			descifrador.init(Cipher.DECRYPT_MODE, kAB1, new IvParameterSpec(ivBytes));

			byte[] loginBytes = descifrador.doFinal(Base64.getDecoder().decode(loginRecibido));
			String login = new String(loginBytes);

			byte[] passwordBytes = descifrador.doFinal(Base64.getDecoder().decode(passwordRecibido));
			String password = new String(passwordBytes);

			// ------------------ PASO 16 ------------------------------

			if (login.equals(loginEsperado) && password.equals(passwordEsperado)) {
				System.out.println("PASO 16: OK");
				escritor.println("OK");
			} else {
				System.out.println("PASO 16: ERROR");
				escritor.println("ERROR");
				clientSocket.close();
				escritor.close();
				lector.close();
				return;
			}

			// ------------------ PASO 19 y 20 ------------------------------

			System.out.println("PASO 19 y 20: RECIBIR CONSULTA CON HMAC Y RESPONDER");
			String consulta = lector.readLine();
			String hmacRecibido = lector.readLine();

			
			Cipher cifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cifrador.init(Cipher.ENCRYPT_MODE, kAB1, new IvParameterSpec(ivBytes));

			String respuestaConsulta = "Los Usuarios son: Santiago, Andrea y Luis";

			byte[] respuestaConsultaCifrado = cifrador.doFinal(respuestaConsulta.getBytes());
			String respuestaConsultaCifradoFinal = Base64.getEncoder().encodeToString(respuestaConsultaCifrado);

			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(kAB2);
			byte[] hmacBytes = mac.doFinal(respuestaConsulta.getBytes());
			String hmac = Base64.getEncoder().encodeToString(hmacBytes);
			escritor.println(respuestaConsultaCifradoFinal);
			escritor.println(hmac);

			clientSocket.close();
			escritor.close();
			lector.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
