package com.spring.crypto.security;

import java.io.Serializable;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CryptoServiceImpl implements CryptoService {
    @Autowired
    private AESCryptoService aesCryptoService;

    @Autowired
    private RSACryptoService rsaCryptoService;

    @Override
    public <T extends Serializable> String encryptAES(T DataToEncrypt, String aesKey, String aesIv) throws Exception {
        return aesCryptoService.encrypt(DataToEncrypt, aesKey, aesIv);
    }

    @Override
    public <T extends Serializable> T decryptAES(String aesCipherText, String aesKey, String aesIv, Class<T> type)
            throws Exception {
        return aesCryptoService.decrypt(aesCipherText, aesKey, aesIv, type);
    }

    @Override
    public <T extends Serializable> String encryptRSA(T data) throws Exception {
        return rsaCryptoService.encryptDataWithRSA(data);
    }

    @Override
    public <T extends Serializable> T decryptRSA(String encryptedData, Class<T> type) throws Exception {
        return rsaCryptoService.decryptRSAData(encryptedData, type);
    }

    @Override
    public <T extends Serializable> String hybridEncrypt(T DataToEncrypt) throws Exception {
        // Encrypt data with AES key
        Map<String, String> aesSignacture = aesCryptoService.generateAESKeyIv();
        String aesKeyBase64 = aesSignacture.get("key").toString();
        String aesIvBase64 = aesSignacture.get("iv").toString();
        String encryptedData = aesCryptoService.encrypt(DataToEncrypt, aesKeyBase64, aesIvBase64);

        String aesKeyIvStr = aesKeyBase64 + ":" + aesIvBase64;
        System.out.println("aesKeyBase64 :"+aesKeyBase64);
        System.out.println("aesIvBase64 :"+ aesIvBase64);
        System.out.println("encryptedMessage :"+ encryptedData);
        // Encrypt AES key with RSA public key
        String encryptedAesKey = rsaCryptoService.encryptDataWithRSA(aesKeyIvStr);

        // Return concatenated encrypted AES key and encrypted data
        return encryptedAesKey + ":" + encryptedData;
    }

    /**
     * Decrypts the given hybrid encrypted data.
     *
     * @param encryptedData the encrypted data to be decrypted
     * @return the decrypted data
     * @throws Exception if an error occurs during decryption
     */
    @Override
    public <T extends Serializable> T hybridDecrypt(String encryptedData, Class<T> type) throws Exception {
        // Split encrypted AES key and encrypted data
        String[] parts = encryptedData.split(":");
        String encryptedAesKey = parts[0];
        String encryptedMessage = parts[1];

        // Decrypt AES key with RSA private key
        String decryptedaesKeyIvStr = rsaCryptoService.decryptRSAData(encryptedAesKey, String.class);
        String[] aesKeyIvStrPart = decryptedaesKeyIvStr.split(":");
        String aesKeyBase64 = aesKeyIvStrPart[0];
        String aesIvBase64 = aesKeyIvStrPart[1];
        System.out.println("aesKeyBase64D :"+aesKeyBase64);
        System.out.println("aesIvBase64D :"+ aesIvBase64);
        System.out.println("encryptedMessageD :"+ encryptedMessage);
        String sanitizedData = encryptedMessage.replaceAll("[^A-Za-z0-9+/=]", "");
        // Decrypt data with decrypted AES key
        return aesCryptoService.decrypt(sanitizedData, aesKeyBase64, aesIvBase64, type);
    }

    @Override
    public  Map<String, String> generateRSAKeyPairPEMFormate(int keysize) throws Exception {
        return rsaCryptoService.generateRSAKeyPairPEMFormate(keysize);
    }
    @Override
    public Map<String, String> getRSAKeyPairkeyId(String keyId) throws Exception {
        return rsaCryptoService.getRSAKeyPairkeyId(keyId);
    }

    @Override
    public  Map<String, String> generateAESKeyIv() throws Exception {
        return aesCryptoService.generateAESKeyIv();
    }


}
