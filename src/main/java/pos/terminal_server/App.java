package pos.terminal_server;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import org.json.JSONObject;

public class App {
	
	private static final int PORT = 12345;
	
    public static void main(String[] args) throws IOException {
    	HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/api/transaction", (HttpExchange exchange) -> {
            handleTransaction(exchange);
        });
        server.start();
        System.out.println("Server listening on port " + PORT);
        
//    	try {
//    		
//	        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
//	            System.out.println("Server listening on port " + PORT);
//	            while (true) {
//	                try (Socket socket = serverSocket.accept()) {
//	                    System.out.println("Client connected, his socket: " + socket);
//	                    
//	                    InputStream inputStream = socket.getInputStream();
//	                    
//	                    DataInputStream dis = new DataInputStream(inputStream);
////	                    ENCRYPTED Session key
//	                    int encryptedKeyLen = dis.readInt();
//	                    byte[] encryptedSessionKey = new byte[encryptedKeyLen];
//	                    dis.readFully(encryptedSessionKey);
//	                    
//	                    String hexStringEncryptedSessionKey = new String(encryptedSessionKey, StandardCharsets.UTF_8);
//	                    
//	                    int length = dis.readInt();
//	                    byte[] strBytes = new byte[length];
//	                    dis.readFully(strBytes);
//
//	                    // Преобразуем байты в строку
//	                    String hexString = new String(strBytes, StandardCharsets.UTF_8);
//
//	                    // Теперь преобразуем hex-строку обратно в байты
//	                    byte[] originalBytes = hexStringToBytes(hexString);
//	                    
//	                    // Читаем строку card
//	                    String card = dis.readUTF();
//
//	                    // Читаем сумму
//	                    int amount = dis.readInt();
//
//	                    // Читаем транзакционный ID
//	                    String transId = dis.readUTF();
//
//	                    // Читаем merchantId
//	                    int merchantId = dis.readInt();
//
//	                    String signature = dis.readUTF();
//	                    
//	                    System.out.println("Get data byte transaction: " + hexString);
//	                    System.out.println("Get card: " + card);
//	                    System.out.println("Get amount: " + amount);
//	                    System.out.println("Get transId: " + transId);
//	                    System.out.println("Get merchantId: " + merchantId);
//	                    System.out.println("Get signatures: " + signature);
//	                    
//	                    System.out.println("Get ENCRYPTED Session key: " + hexStringEncryptedSessionKey);
//	                 // Расшифровка
//	                    PrivateKey serverPrivateKey = getPrivateKeyFromPEM("C:/My Disc/app/1-JAVA APP/PEM/private_key.pem");
//	                    System.out.println("Private Key: " + serverPrivateKey);
//	                    SecretKey sessionEncryptedKey = decryptSessionKeyRSA(encryptedSessionKey, serverPrivateKey);
//	                    System.out.println("Decoded session key: " + java.util.Base64.getEncoder().encodeToString(sessionEncryptedKey.getEncoded()));
//
//	                } catch (Exception e) {
//	                    e.printStackTrace();
//	                }
//	            }
//	        } catch (IOException e1) {
//				e1.printStackTrace();
//			}
//    	} catch (Exception e) {
//    		System.out.println("Error method loadPrivateKey()");
//			e.printStackTrace();
//		}
    }   
    
    
    private static void handleTransaction(HttpExchange exchange) throws IOException {
        if ("POST".equals(exchange.getRequestMethod())) {
            InputStream is = exchange.getRequestBody();
            BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            StringBuilder requestBody = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                requestBody.append(line);
            }
            reader.close();

            System.out.println("Полученные данные: " + requestBody.toString());

            JSONObject jsonReceived = new JSONObject(requestBody.toString());

            String cardNumber = jsonReceived.getString("cardNumber");
            int amount = jsonReceived.getInt("amount");
            String merchantId = jsonReceived.getString("merchantId");
            String transactionBytesHex = jsonReceived.getString("transactionBytes");

            byte[] transactionBytes = hexStringToByteArray(transactionBytesHex);

            System.out.println("Card Number: " + cardNumber);
            System.out.println("Amount: " + amount);
            System.out.println("Merchant ID: " + merchantId);
            System.out.println("Transaction Bytes: " + new String(transactionBytes));

            String response = "Данные успешно получены и распарсены";

            exchange.sendResponseHeaders(200, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        } else {
            exchange.sendResponseHeaders(405, -1);
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
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
    
    
    
    public static SecretKey decryptSessionKeyRSA(byte[] encryptedSessionKeyBytes, PrivateKey privateKey) throws Exception {
        // Преобразуем байты в Hex-строку
        String hexString = new String(encryptedSessionKeyBytes, StandardCharsets.UTF_8);
        // Декодируем Hex-строку обратно в байты
        byte[] encryptedBytes = hexStringToBytes(hexString);
        
        // Инициализация Cipher для RSA OAEP
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        // Расшифровка байтов
        byte[] sessionKeyBytes = cipher.doFinal(encryptedBytes);
        
        // Восстановление SecretKey, AES
        return new SecretKeySpec(sessionKeyBytes, "AES");
    }
    

    public static PrivateKey getPrivateKeyFromPEM(String filename) throws Exception {
            String pem = new String(Files.readAllBytes(Paths.get(filename)), StandardCharsets.UTF_8);
            pem = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                     .replace("-----END PRIVATE KEY-----", "")
                     .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(pem);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }

}
