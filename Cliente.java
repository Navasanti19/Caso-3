import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;

public class Cliente extends Thread{

	private final String serverAddress;
    private final int serverPort;
	private final int id;

	public Cliente(String serverAddress, int serverPort, int id) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
		this.id = id;
    }
	public void run(){
		String mensajito = "SECURE INIT CLIENTE";

		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

		PublicKey publicKey = null;
		BigInteger gxy = null;

		try {

			// --------------- LEER LLAVE PUBLICA DEL SERVIDOR ---------------

			//System.out.println("Comienza cliente" + id);
			
			// Leer los bytes de la llave pública desde el archivo
			byte[] publicKeyBytes = Files.readAllBytes(Paths.get("publicKey.key"));

			// Convertir los bytes a una PublicKey
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(keySpec);

			socket = new Socket(serverAddress, serverPort);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));



			// --------------------- PASO 1 ----------------------

			System.out.println("PASO 1 SECURE INIT");
			escritor.println(mensajito);

		
		
			// --------------------- PASO 4 ----------------------

			System.out.println("PASO 4: VERIFICAR FIRMA");
			long startTime = System.nanoTime();
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);

			String encodedMessage = lector.readLine();
			byte[] encryptedMessage = Base64.getDecoder().decode(encodedMessage);

			signature.update(mensajito.getBytes());
			boolean isCorrect = signature.verify(encryptedMessage);
			long endTime = System.nanoTime();
			ClienteGrande.timeVerifySignature.addAndGet(endTime - startTime);

			// --------------------- PASO 5 ----------------------

			if (isCorrect) {
                System.out.println("PASO 5: OK");
                escritor.println("OK");
            } else {
                System.out.println("PASO 5: ERROR");
                escritor.println("ERROR");
            }

			
			// --------------------- PASO 8 ----------------------
			
			String pRecibida = lector.readLine();
			String gRecibida = lector.readLine();
			String gxRecibida = lector.readLine();
			String ivRecibido = lector.readLine();
			
			System.out.println("PASO 8: VERIFICAR P,G, GX");
			String datosRecibidos = lector.readLine();
			String datosCifrados = lector.readLine();
			byte[] firmaRecibida = Base64.getDecoder().decode(datosCifrados);

			signature.update(datosRecibidos.getBytes());
			boolean verificado = signature.verify(firmaRecibida);

			// --------------------- PASO 9 ----------------------

			if (verificado) {
				System.out.println("PASO 9: OK");
				escritor.println("OK");
			} else {
				System.out.println("PASO 9: ERROR");
				escritor.println("ERROR");
				socket.close();
				escritor.close();
				lector.close();
				return;
			}

			// --------------------- PASO 10 ----------------------

			System.out.println("PASO 10: CALCULAR Y MANDAR GY");
			byte[] pBytes = Base64.getDecoder().decode(pRecibida);
			byte[] gxBytes = Base64.getDecoder().decode(gxRecibida);
			BigInteger p = new BigInteger(pBytes);
			BigInteger g = new BigInteger(gRecibida);
			BigInteger gx = new BigInteger(gxBytes);

			startTime = System.nanoTime();
			SecureRandom random = new SecureRandom();
			BigInteger y = new BigInteger(p.bitLength() - 2, random);
			BigInteger gy = g.modPow(y, p);
			endTime = System.nanoTime();
			ClienteGrande.timeCalculateGy.addAndGet(endTime - startTime);

			escritor.println(Base64.getEncoder().encodeToString(gy.toByteArray()));

			// --------------------- PASO 11A ----------------------

			System.out.println("PASO 11a: CALCULAR LLAVES");
			gxy = gx.modPow(y, p);

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

			String continuar = lector.readLine();
			if (!continuar.equals("CONTINUAR")) {
				socket.close();
				escritor.close();
				lector.close();
				return;
			}

			// --------------------- PASO 13 y 14 ----------------------

			System.out.println("PASO 13 - 14: CIFRAR Y MANDAR LOGIN Y PASSWORD");

			String login = "s.navarretev";
			String password = "C0ntr4s3n4";

			byte[] ivBytes = Base64.getDecoder().decode(ivRecibido);
			Cipher cifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cifrador.init(Cipher.ENCRYPT_MODE, kAB1, new IvParameterSpec(ivBytes));

			byte[] loginCifrado = cifrador.doFinal(login.getBytes());
			String loginCifradoFinal = Base64.getEncoder().encodeToString(loginCifrado);

			byte[] pwdCifrado = cifrador.doFinal(password.getBytes());
			String pwdCifradoFinal = Base64.getEncoder().encodeToString(pwdCifrado);

			escritor.println(loginCifradoFinal);
			escritor.println(pwdCifradoFinal);

			// --------------------- PASO 17 y 18 ----------------------

			System.out.println("PASO 17 - 18 CIFRAR Y ENVIAR CONSULTA CON HMAC");

			String respuesta16 = lector.readLine();
			if (!respuesta16.equals("OK")) {
				socket.close();
				escritor.close();
				lector.close();
				return;
			}

			startTime = System.nanoTime();
			String consulta = "SELECT * FROM USUARIOS";

			byte[] consultaCifrado = cifrador.doFinal(consulta.getBytes());
			String consultaCifradoFinal = Base64.getEncoder().encodeToString(consultaCifrado);
			endTime = System.nanoTime();
			ClienteGrande.timeEncryptQuery.addAndGet(endTime - startTime);

			startTime = System.nanoTime();
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(kAB2);
			byte[] hmacBytes = mac.doFinal(consulta.getBytes());
			String hmac = Base64.getEncoder().encodeToString(hmacBytes);
			endTime = System.nanoTime();
			ClienteGrande.timeGenerateAuthCode.addAndGet(endTime - startTime);

			escritor.println(consultaCifradoFinal);
			escritor.println(hmac);

			// --------------------- PASO 21 ----------------------

			System.out.println("PASO 21: RECIBIR RESPUESTA CON HMAC");
			String respuestaConsultaCifrado = lector.readLine();
			String hmacRecibido = lector.readLine();

			startTime = System.nanoTime();
			byte[] hmacRecibidoBytes = Base64.getDecoder().decode(hmacRecibido);

			Cipher descifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
			descifrador.init(Cipher.DECRYPT_MODE, kAB1, new IvParameterSpec(ivBytes));

			byte[] respuestaCifradaBytes = Base64.getDecoder().decode(respuestaConsultaCifrado);
			byte[] respuestaDescifradaBytes = descifrador.doFinal(respuestaCifradaBytes);
			String respuestaDescifrada = new String(respuestaDescifradaBytes);
			endTime = System.nanoTime();
			ClienteGrande.timeDecryptQuery.addAndGet(endTime - startTime);

			startTime = System.nanoTime();
			byte[] hmacCalculado = mac.doFinal(respuestaDescifrada.getBytes());

			if (Arrays.equals(hmacRecibidoBytes, hmacCalculado)) {
				System.out.println("TODO BIEN EXCELENTE");
			} else {
				System.out.println("Error: La respuesta ha sido alterada o el HMAC no coincide.");
			}
			endTime = System.nanoTime();
			ClienteGrande.timeVerifyAuthCode.addAndGet(endTime - startTime);

			socket.close();
			escritor.close();
			lector.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
