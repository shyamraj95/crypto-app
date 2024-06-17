package com.spring.crypto.security;

import java.io.Serializable;
import java.util.Map;

public interface CryptoService {
    <T extends Serializable> String encryptAES(T input, String key, String iv) throws Exception;

    <T extends Serializable> T decryptAES(String cipherText, String key, String iv, Class<T> type) throws Exception;

    <T extends Serializable> String encryptRSA(T data) throws Exception;

    <T extends Serializable> T decryptRSA(String encryptedData, Class<T> type) throws Exception;

    <T extends Serializable> String hybridEncrypt(T DataToEncrypt) throws Exception;

    <T extends Serializable> T hybridDecrypt(String encryptedData, Class<T> type) throws Exception;

    Map<String, String> generateRSAKeyPairPEMFormate(int keysize) throws Exception;

    Map<String, String> getRSAKeyPairkeyId(String keyId) throws Exception;

    Map<String, String> generateAESKeyIv() throws Exception;
}
