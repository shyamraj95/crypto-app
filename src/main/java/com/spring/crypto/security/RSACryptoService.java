package com.spring.crypto.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.spring.crypto.exception.CryptoException;

@Component
public class RSACryptoService {
    private static final String RSA = "RSA";
    private final Map<String, Map<String, String>> keyStore = new HashMap<>();
    @Value("${rsa.private-key-path}")
    private String privateKeyPath;

    @Value("${rsa.public-key-path}")
    private String publicKeyPath;

    private PublicKey rsaPublicKey;
    private PrivateKey rsaPrivateKey;

    @PostConstruct
    public void init() throws Exception {
        // generateRSAKeyPairPEMFormate();
        rsaPublicKey = loadPublicKey(publicKeyPath);
        rsaPrivateKey = loadPrivateKey(privateKeyPath);

    }

    public <T extends Serializable> String encryptDataWithRSA(T dataToEncrypct) throws Exception {
        if (dataToEncrypct != null)
            return encrypt(dataToEncrypct, rsaPublicKey);
        else
            throw new CryptoException("Data to encrypt cannot be null");
    }

    public <T extends Serializable> T decryptRSAData(String dataToDecrypt, Class<T> type) throws Exception {
        System.out.println(dataToDecrypt);
        if (dataToDecrypt != null)
            return decrypt(dataToDecrypt, rsaPrivateKey, type);
        else
            throw new CryptoException("Data to decrypt cannot be null");
    }

    /**
     * Encrypts the given data using RSA encryption with the provided public key.
     *
     * @param <T>        the type of the data to be encrypted
     * @param data       the data to be encrypted
     * @param publicKey  the public key used for encryption
     * @return           the base64-encoded cipher text
     * @throws Exception if there is an error during encryption
     */
    private <T extends Serializable> String encrypt(T data, PublicKey publicKey) throws Exception {
        // Create a Cipher instance for encryption
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Serialize the data to bytes
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(data);
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
     * Decrypts the given cipher text using RSA encryption with the provided private key.
     *
     * @param <T>        the type of the decrypted object
     * @param data       the base64-encoded encrypted data
     * @param privateKey the private key used for decryption
     * @param type       the class of the decrypted object
     * @return the decrypted object of type T
     * @throws Exception if there is an error during decryption or casting
     */
    public <T extends Serializable> T decrypt(String data, PrivateKey privateKey, Class<T> type)
            throws Exception {
        try {
            // Create a Cipher instance for decryption
            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Remove any illegal characters (like '{') before decoding
            String sanitizedData = data.replaceAll("[^A-Za-z0-9+/=]", "");

            // Decode the base64-encoded data
            byte[] decodedData = Base64.getDecoder().decode(sanitizedData);

            // Perform the decryption
            byte[] plainText = cipher.doFinal(decodedData);

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
        } catch (ClassCastException | ClassNotFoundException | IllegalArgumentException e) {
            // Throw a custom exception if decryption or casting fails
            throw new CryptoException("RSA decryption failed", e);
        }
    }

    /**
     * Load a public key from a PEM-encoded file.
     *
     * @param keyPath the path to the PEM-encoded file
     * @return the loaded public key
     * @throws Exception if there is an error during key loading
     */
    private PublicKey loadPublicKey(String keyPath) throws Exception {
        // Read the PEM-encoded key file
        byte[] keyBytes = readPemFile(keyPath);

        // Create a X509EncodedKeySpec from the key bytes
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

        // Create a KeyFactory for the RSA algorithm
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);

        // Generate the public key from the key spec
        return keyFactory.generatePublic(spec);
    }


    /**
     * Load a private key from a PEM-encoded file.
     *
     * @param keyPath the path to the PEM-encoded file
     * @return the loaded private key
     * @throws Exception if there is an error during key loading
     */
    private PrivateKey loadPrivateKey(String keyPath) throws Exception {
        // Read the PEM-encoded key file
        byte[] keyBytes = readPemFile(keyPath);

        // Create a PKCS8EncodedKeySpec from the key bytes
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        // Create a KeyFactory for the RSA algorithm
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);

        // Generate the private key from the key spec
        return keyFactory.generatePrivate(spec);
    }

    /**
     * Generates an RSA key pair and returns it in PEM format.
     *
     * @param keysize the size of the key to generate
     * @return a map containing the private key, public key, and key ID in PEM format
     * @throws Exception if there is an error generating the key pair
     */
    public Map<String, String> generateRSAKeyPairPEMFormate(int keysize) throws Exception {
        // Generate an RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keysize);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // Get the private and public keys
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Create a map to store the key pair
        Map<String, String> keyPairMap = new HashMap<>();
        
        // Add the private key to the map in PEM format
        keyPairMap.put("privateKey", convertToPEM(privateKey));
        
        // Add the public key to the map in PEM format
        keyPairMap.put("publicKey", convertToPEM(publicKey));
        
        // Generate a random key ID
        String keyId = UUID.randomUUID().toString();
        
        // Add the key pair to the key store with the key ID
        keyStore.put(keyId, keyPairMap);
        
        // Add the key ID to the key pair map
        keyPairMap.put("keyId", keyId);
        
        // Return the key pair map
        return keyPairMap;
    }

    public Map<String, String> getRSAKeyPairkeyId(String keyId) {
        return keyStore.get(keyId);
    }

    private byte[] readPemFile(String path) throws IOException {
        String pem = new String(Files.readAllBytes(Paths.get(path)));
        // removes headers, footers, and whitespace (including line breaks), then
        // decodes it from Base64.
        pem = pem.replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(pem);
    }

    private String convertToPEM(PublicKey publicKey) {
        String encoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n"
                + encoded.replaceAll("(.{64})", "$1\n")
                + "\n-----END PUBLIC KEY-----";
        return publicKeyPEM;
    }

    private String convertToPEM(PrivateKey privateKey) {
        final String encoded = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" +
                encoded.replaceAll("(.{64})", "$1\n") +
                "\n-----END PRIVATE KEY-----";
    }

}
