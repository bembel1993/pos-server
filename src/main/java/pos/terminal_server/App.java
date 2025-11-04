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

import pos.terminal_server.TransactionData;

import com.sun.net.httpserver.HttpExchange;

import org.json.JSONException;
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

            try {
                JSONObject jsonReceived = new JSONObject(requestBody.toString());

                String transactionBytesHex = jsonReceived.getString("transactionBytes");

                byte[] transactionBytes = hexStringToByteArray(transactionBytesHex);
                
                System.out.println("----------- DECODE TRANSACTION ---------------");
                TransactionData data = decodeTransaction(transactionBytes);
                String card = data.getCardNumber();
                int amount = data.getAmount();
                String transId = data.getTransId();
                int merchtId = data.getMerchantId();

                JSONObject responseJson = new JSONObject();
                responseJson.put("status", "success");

                String response = responseJson.toString();

                exchange.sendResponseHeaders(200, response.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            } catch (JSONException e) {
                e.printStackTrace();
                String errorResponse = "Ошибка парсинга JSON: " + e.getMessage();
                exchange.sendResponseHeaders(400, errorResponse.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(errorResponse.getBytes());
                }
            } catch (Exception e) {
                e.printStackTrace();
                String errorResponse = "Общая ошибка: " + e.getMessage();
                exchange.sendResponseHeaders(500, errorResponse.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(errorResponse.getBytes());
                }
            }
        } else {
            exchange.sendResponseHeaders(405, -1);
        }
    }

    private static byte[] hexStringToByteArray(String s) {
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
    
    
    public static TransactionData decodeTransaction(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);

        byte[] cardBytes = new byte[20];
        buffer.get(cardBytes);
        String card = new String(cardBytes, StandardCharsets.UTF_8).trim();

        int amount = buffer.getInt();

        byte[] transIdBytes = new byte[50];
        buffer.get(transIdBytes);
        String transId = new String(transIdBytes, StandardCharsets.UTF_8).trim();

        int merchantId = buffer.getInt();

        System.out.println("Card PAN: " + card);
        System.out.println("Amount: " + amount);
        System.out.println("UUID: " + transId);
        System.out.println("Merchant ID: " + merchantId);
        
        TransactionData trData = new TransactionData(card, amount, transId, merchantId);
        
        return trData;
    }

}
