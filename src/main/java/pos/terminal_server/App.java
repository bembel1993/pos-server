package pos.terminal_server;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class App {
	
	private static final int PORT = 12345;
	
    public static void main(String[] args) {
    	// Загрузка приватного RSA-ключа сервера
    	try {
//    		PrivateKey privateKey = loadPrivateKey();
		
	        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
	            System.out.println("Server listening on port " + PORT);
	            while (true) {
	                try (Socket socket = serverSocket.accept()) {
	                    System.out.println("Client connected, his socket: " + socket);
	                    
	                    InputStream inputStream = socket.getInputStream();
	                    
	                    DataInputStream dis = new DataInputStream(inputStream);
	                    
	                    int length = dis.readInt();
	                    byte[] strBytes = new byte[length];
	                    dis.readFully(strBytes);

	                    // Преобразуем байты в строку
	                    String hexString = new String(strBytes, StandardCharsets.UTF_8);

	                    // Теперь преобразуем hex-строку обратно в байты
	                    byte[] originalBytes = hexStringToBytes(hexString);
	                    
	                    // Читаем строку card
	                    String card = dis.readUTF();

	                    // Читаем сумму
	                    int amount = dis.readInt();

	                    // Читаем транзакционный ID
	                    String transId = dis.readUTF();

	                    // Читаем merchantId
	                    int merchantId = dis.readInt();

	                    String signature = dis.readUTF();
	                    
	                    System.out.println("Get data byte transaction: " + hexString);
	                    System.out.println("Get card: " + card);
	                    System.out.println("Get amount: " + amount);
	                    System.out.println("Get transId: " + transId);
	                    System.out.println("Get merchantId: " + merchantId);
	                    System.out.println("Get signatures: " + signature);
//	                    BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
//	                    String transactionByte;
//	                    while ((transactionByte = reader.readLine()) != null) {
//	                        System.out.println("Get data byte transaction: " + transactionByte);
//	                    }
//	                    handleClient(socket, privateKey);
	                } catch (Exception e) {
	                    e.printStackTrace();
	                }
	            }
	        } catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
    	} catch (Exception e) {
			// TODO Auto-generated catch block
    		System.out.println("Error method loadPrivateKey()");
			e.printStackTrace();
		}
    }
    
    private static void handleClient(Socket socket, PrivateKey privateKey) throws Exception {
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

        // Предположим, сначала приходит длина RSA-зашифрованного ключ
        int encryptedKeyLen = dis.readInt();
        byte[] encryptedSessionKey = new byte[encryptedKeyLen];
        dis.readFully(encryptedSessionKey);

        // Расшифровка RSA
        byte[] sessionKeyBytes = rsaDecrypt(encryptedSessionKey, privateKey);
        SecretKey sessionKey = new javax.crypto.spec.SecretKeySpec(sessionKeyBytes, "AES");

        // Получение длины зашифрованного payload
        int encryptedPayloadLen = dis.readInt();
        byte[] encryptedPayload = new byte[encryptedPayloadLen];
        dis.readFully(encryptedPayload);

        // Расшифровка AES-GCM
        byte[] payload = aesGcmDecrypt(encryptedPayload, sessionKey);

        // Предположим, что внутри payload у нас TLV или данные, включая HMAC
        // Здесь нужно реализовать проверку HMAC, например, извлекая его из payload
        // Для примера, просто выводим расшифрованные данные
        System.out.println("Decrypted payload: " + new String(payload, "UTF-8"));

        // Проверка HMAC — зависит от формата данных (например, HMAC внутри payload или отдельное поле)
        // Тут нужно реализовать проверку HMAC, например:
        // boolean isValid = verifyHMAC(payload, receivedHmac, sharedSecret)
    }

    private static byte[] rsaDecrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private static byte[] aesGcmDecrypt(byte[] encryptedData, SecretKey key) throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
        byte[] iv = new byte[12];
        byteBuffer.get(iv);
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(cipherText);
    }

    private static PrivateKey loadPrivateKey() throws Exception {
        // Вставьте сюда ваш приватный ключ в PEM-формате (без лишних символов)
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n ваш базовый64 ключ тут\n -----END PRIVATE KEY-----";

        // Убираем заголовки, переносы и пробелы
        String privateKeyContent = privateKeyPEM
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        // Декодируем Base64
        byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(privateKeyContent);

        // Создаем ключ
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    // Реализуйте verifyHMAC() согласно выбранной схеме
    
    
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] hexStringToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
