package com.spring.crypto.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

@Service
public class AESCryptoService {
    private static final String AES_CBC = "AES/CBC/PKCS5PADDING";

    /**
     * Generates a random AES key of size 256 bits.
     *
     * @return The generated key as a Base64-encoded string.
     * @throws NoSuchAlgorithmException if the AES key generation algorithm is not available.
     */
    private String generateKey() throws NoSuchAlgorithmException {
        // Create a KeyGenerator instance for AES encryption.
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");

        // Initialize the KeyGenerator with a key size of 256 bits.
        keyGen.init(256);

        // Generate a new AES secret key.
        SecretKey key = keyGen.generateKey();

        // Return the key as a Base64-encoded string.
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    private String generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    /**
     * Encrypts the given data using AES encryption with the provided key and IV.
     *
     * @param <T>           the type of the data to be encrypted
     * @param dataToEncrypt the data to be encrypted
     * @param keyBase64     the base64-encoded AES key
     * @param ivBase64      the base64-encoded AES IV
     * @return the base64-encoded encrypted data
     * @throws Exception if there is an error during encryption
     */
    public <T extends Serializable> String encrypt(T dataToEncrypt, String keyBase64, String ivBase64)
            throws Exception {
        // Decode the base64-encoded key and IV
        SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(keyBase64), "AES");
        IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(ivBase64));

        // Create a Cipher instance for encryption
        Cipher cipher = Cipher.getInstance(AES_CBC);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        // Serialize the data to bytes
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(dataToEncrypt);
        oos.flush();
        byte[] inputBytes = bos.toByteArray();
        oos.close();
        bos.close();

        // Perform the encryption
        byte[] cipherText = cipher.doFinal(inputBytes);

        // Encode the cipher text to base64 string
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * Decrypts the given cipher text using AES encryption with the provided key and
     * IV.
     *
     * @param <T>        the type of the decrypted object
     * @param cipherText the base64-encoded encrypted data
     * @param keyBase64  the base64-encoded AES key
     * @param ivBase64   the base64-encoded AES IV
     * @param type       the class of the decrypted object
     * @return the decrypted object of type T
     * @throws Exception if there is an error during decryption or casting
     */
    public <T extends Serializable> T decrypt(String cipherText, String keyBase64, String ivBase64,
            Class<T> type) throws Exception {
        // Decode the base64-encoded key and IV
        SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(keyBase64), "AES");
        IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(ivBase64));

        // Create a Cipher instance for decryption
        Cipher cipher = Cipher.getInstance(AES_CBC);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        // Decode the base64-encoded cipher text
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));

        // Create ByteArrayInputStream and ObjectInputStream to read the decrypted data
        ByteArrayInputStream bis = new ByteArrayInputStream(plainText);
        ObjectInputStream ois = new ObjectInputStream(bis);

        // Read and cast the decrypted object
        @SuppressWarnings("unchecked")
        T obj = (T) ois.readObject();

        // Close the streams
        ois.close();
        bis.close();

        return obj;
    }

    /**
     * Generates a map containing the AES key and initialization vector (IV) for
     * encryption.
     *
     * @return a map with the keys "key" and "iv", containing the generated AES key
     *         and IV respectively
     * @throws Exception if an error occurs during key or IV generation
     */
    public Map<String, String> generateAESKeyIv() throws Exception {
        // Create a map to store the key and IV
        Map<String, String> aesKeyIvMap = new HashMap<>();

        // Generate the AES key and add it to the map
        String key = generateKey();
        aesKeyIvMap.put("key", key);

        // Generate the AES IV and add it to the map
        String iv = generateIv();
        aesKeyIvMap.put("iv", iv);

        // Return the map containing the key and IV
        return aesKeyIvMap;
    }
}
