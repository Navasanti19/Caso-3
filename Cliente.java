import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

public class Cliente {

	public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";

	public static void main(String[] args) throws IOException {

		String mensajito = "Reto";

		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;

		PublicKey publicKey = null;
		BigInteger gxy = null;

		System.out.println("Comienza cliente");
		try {
			// Leer los bytes de la llave pública desde el archivo
			byte[] publicKeyBytes = Files.readAllBytes(Paths.get("publicKey.key"));

			// Convertir los bytes a una PublicKey
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(keySpec);

			System.out.println("Public Key imported successfully");

			// Aquí puedes usar la llave pública para operaciones criptográficas
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println("Error importing public key: " + e.getMessage());
		}

		try {
			socket = new Socket(SERVIDOR, PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("PASO 1 SECURE INIT");
		escritor.println(mensajito);

		// Verifica el mensaje cifrado
		try {
			// Configurar Cipher para usar RSA en modo DECRYPT
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);

			// Supongamos que este es el mensaje "cifrado" recibido
			String encodedMessage = lector.readLine();
			byte[] encryptedMessage = Base64.getDecoder().decode(encodedMessage);
			// System.out.println("Mensaje cifrado recibido: " + encodedMessage);

			// Descifrar el mensaje
			byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
			// System.out.println("Mensaje descifrado: " + new String(decryptedMessage));

			System.out.println("PASO 4: VERIFICAR MENSAJE");
			if (new String(decryptedMessage).equals(mensajito)) {
				System.out.println("PASO 5: OK");
				escritor.println("OK");
				System.out.println("OK");
			} else {
				System.out.println("PASO 5: ERROR");
				escritor.println("ERROR");
				System.out.println("ERROR");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		try {
			String pRecibida = lector.readLine();
			String gRecibida = lector.readLine();
			String gxRecibida = lector.readLine();
			String ivRecibido = lector.readLine();

			System.out.println("PASO 8: VERIFICAR P,G, GX");
			String datosRecibidos = lector.readLine();
			String datosCifrados = lector.readLine();
			byte[] firmaRecibida = Base64.getDecoder().decode(datosCifrados);

			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(publicKey);
			signature.update(datosRecibidos.getBytes());
			boolean verificado = signature.verify(firmaRecibida);

			if (verificado) {
				System.out.println("PASO 9: OK");
				// System.out.println("P,G, GX verificada");
				escritor.println("OK");
			} else {
				System.out.println("PASO 9: ERROR");
				// System.out.println("P,G, GX no verificada");
				escritor.println("ERROR");
				return;
			}
			System.out.println("PASO 10: CALCULAR Y MANDAR GY");
			byte[] pBytes = Base64.getDecoder().decode(pRecibida);
			byte[] gxBytes = Base64.getDecoder().decode(gxRecibida);
			BigInteger p = new BigInteger(pBytes);
			BigInteger g = new BigInteger(gRecibida);
			BigInteger gx = new BigInteger(gxBytes);

			SecureRandom random = new SecureRandom();
			BigInteger y = new BigInteger(p.bitLength() - 2, random);
			BigInteger gy = g.modPow(y, p);

			escritor.println(Base64.getEncoder().encodeToString(gy.toByteArray()));

			System.out.println("PASO 11b: CALCULAR LLAVE");
			gxy = gx.modPow(y, p);

		} catch (Exception e) {
			e.printStackTrace();
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
