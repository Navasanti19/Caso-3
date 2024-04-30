import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Servidor {

	private static final int PUERTO = 3400;

	public static void main(String[] args) throws IOException {

		ServerSocket ss = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		boolean continuar = true;

		KeyPair pair = null;
		BigInteger gxy = null;

		System.out.println("Comienza servidor");

		try {
			// Generar el par de llaves
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			pair = keyGen.generateKeyPair();
			PublicKey publicKey = pair.getPublic();

			// Convertir la llave pública a formato X.509
			byte[] publicKeyBytes = publicKey.getEncoded();

			// Guardar la llave pública en un archivo
			Files.write(Paths.get("publicKey.key"), publicKeyBytes);
			System.out.println("Public key saved to publicKey.key");

		} catch (NoSuchAlgorithmException | IOException e) {
			System.out.println("Error generating/saving public key: " + e.getMessage());
		}

		try {
			ss = new ServerSocket(PUERTO);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}

		Socket socket = ss.accept();

		try {
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		} catch (Exception e) {
			e.printStackTrace();
		}

		try {

			// cifrar el mensaje recibido
			PrivateKey privateKey = pair.getPrivate();

			// Configurar Cipher para usar RSA
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);

			// Mensaje a cifrar
			System.out.println("PASO 2 CIFRAR MENSAJE");
			String mensaje = lector.readLine();
			byte[] messageBytes = mensaje.getBytes();

			// Cifrar el mensaje
			byte[] encryptedMessage = cipher.doFinal(messageBytes);
			String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
			System.out.println("PASO 3: ENVIAR MENSAJE CIFRADO");
			escritor.println(encodedMessage);
			// System.out.println("Mensaje cifrado enviado: " + encodedMessage);

		} catch (Exception e) {
			System.out.println("Error al cifrar con la llave privada: " + e.toString());
		}

		String respuesta5 = lector.readLine();
		if (respuesta5.equals("ERROR")) {
			return;
		}

		try {
			System.out.println("PASO 7: ENVIAR P, G, GX");
			String pHex = new String(Files.readAllBytes(Paths.get("P.txt"))).trim(); // Lee y elimina espacios
			BigInteger p = new BigInteger(pHex, 16); // Convierte de hexadecimal a BigInteger

			BigInteger g = BigInteger.valueOf(2);

			SecureRandom random = new SecureRandom();
			BigInteger x = new BigInteger(1024 - 2, random);
			BigInteger gx = g.modPow(x, p);

			byte[] iv = new byte[16];
			new SecureRandom().nextBytes(iv);

			String pBase64 = Base64.getEncoder().encodeToString(p.toByteArray());
			String gxBase64 = Base64.getEncoder().encodeToString(gx.toByteArray());
			String ivBase64 = Base64.getEncoder().encodeToString(iv);

			String datos = pBase64 + "|" + g + "|" + gxBase64;

			escritor.println(pBase64);
			escritor.println("2"); // G es 2
			escritor.println(gxBase64);
			escritor.println(ivBase64);

			escritor.println(datos);

			PrivateKey privateKey = pair.getPrivate();
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(privateKey);
			signature.update(datos.getBytes());
			byte[] firma = signature.sign();

			String encodedMessage = Base64.getEncoder().encodeToString(firma);
			escritor.println(encodedMessage);

			String respuesta9 = lector.readLine();
			if (respuesta9.equals("ERROR")) {
				return;
			}

			String gyBase64 = lector.readLine();
			byte[] gyBytes = Base64.getDecoder().decode(gyBase64);
			BigInteger gy = new BigInteger(gyBytes);

			System.out.println("PASO 11a: CALCULAR LLAVE");
			gxy = gy.modPow(x, p);

		} catch (Exception e) {
			System.out.println("Error al enviar datos: " + e.toString());
		}
		try {
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
			SecretKey kAB2 = new SecretKeySpec(claveDerivada, "AES");

		} catch (Exception e) {
			e.printStackTrace();
		}

		socket.close();
		escritor.close();
		lector.close();

	}

}
