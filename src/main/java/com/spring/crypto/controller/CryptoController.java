package com.spring.crypto.controller;

import java.io.ByteArrayInputStream;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.spring.crypto.dto.RSAKeyPairRespDto;
import com.spring.crypto.dto.aesEncryptionReqDto;
import com.spring.crypto.security.CryptoService;

import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/crypto")
public class CryptoController {
    @Autowired
    private CryptoService cryptoService;

 /**
     * Generates a RSA key pair in PEM format.
     *
     * @param  keysize  the size of the RSA key pair to generate (in bits)
     * @return           a ResponseEntity containing the RSA key pair as a RSAKeyPairRespDto
     * @throws RuntimeException if there is an error generating the key pair
     */
    @GetMapping("/generateRSAKeyPaire")
    public ResponseEntity<RSAKeyPairRespDto> generateKeys(@RequestBody int keysize) {
        try {
            // Generate RSA key pair using the CryptoService
            Map<String, String> keyPair = cryptoService.generateRSAKeyPairPEMFormate(keysize);

            // Create a new RSAKeyPairRespDto object to hold the key pair
            RSAKeyPairRespDto response = new RSAKeyPairRespDto();

            // Set the public key and private key in the response object
            response.setPublicKey(keyPair.get("publicKey"));
            response.setPrivateKey(keyPair.get("privateKey"));

            // Set the download URLs for the public and private keys
            response.setPublicKeyDownloadUrl("/download-public-key?keyId=" + keyPair.get("keyId"));
            response.setPrivateKeyDownloadUrl("/download-private-key?keyId=" + keyPair.get("keyId"));

            // Return the response object as a successful ResponseEntity
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // Wrap any exceptions in a RuntimeException and re-throw
            throw new RuntimeException("Error generating key pair", e);
        }
    }

    /**
     * Download a public key based on the provided key ID.
     * 
     * @param keyId the ID of the key pair to download the public key from
     * @return a ResponseEntity containing the public key as an InputStreamResource
     * @throws RuntimeException if there is an error generating the public key
     */
    @GetMapping("/download-public-key")
    public ResponseEntity<InputStreamResource> downloadPublicKey(@RequestParam String keyId) {
        try {
            // Get the public key from the CryptoService based on the provided key ID
            Map<String, String> keyPair = cryptoService.getRSAKeyPairkeyId(keyId);

            // If the key pair is not found, return a 404 response
            if (keyPair == null) {
                return ResponseEntity.notFound().build();
            }

            // Get the public key from the key pair
            String publicKeyPEM = keyPair.get("publicKey");

            // Create an InputStreamResource from the public key PEM string
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(publicKeyPEM.getBytes());

            // Create HTTP headers with a Content-Disposition for the downloaded file
            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Disposition", "attachment; filename=public_key.pem");

            // Return a ResponseEntity with the public key as an InputStreamResource
            return ResponseEntity.ok()
                    .headers(headers)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(new InputStreamResource(byteArrayInputStream));
        } catch (Exception e) {
            // Wrap any exceptions in a RuntimeException and re-throw
            throw new RuntimeException("Error generating public key", e);
        }
    }

    /**
     * Download a private key based on the provided key ID.
     * 
     * @param keyId the ID of the key pair to download the private key from
     * @return a ResponseEntity containing the private key as an InputStreamResource
     * @throws RuntimeException if there is an error generating the private key
     */
    @GetMapping("/download-private-key")
    public ResponseEntity<InputStreamResource> downloadPrivateKey(@RequestParam String keyId) {
        try {
            // Get the private key from the CryptoService based on the provided key ID
            Map<String, String> keyPair = cryptoService.getRSAKeyPairkeyId(keyId);

            // If the key pair is not found, return a 404 response
            if (keyPair == null) {
                return ResponseEntity.notFound().build();
            }

            // Get the private key from the key pair
            String privateKeyPEM = keyPair.get("privateKey");

            // Create an InputStreamResource from the private key PEM string
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(privateKeyPEM.getBytes());

            // Create HTTP headers with a Content-Disposition for the downloaded file
            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Disposition", "attachment; filename=private_key.pem");

            // Return a ResponseEntity with the private key as an InputStreamResource
            return ResponseEntity.ok()
                    .headers(headers)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(new InputStreamResource(byteArrayInputStream));
        } catch (Exception e) {
            // Wrap any exceptions in a RuntimeException and re-throw
            throw new RuntimeException("Error generating private key", e);
        }
    }

    @GetMapping("/generateAESKeyIv")
    public Map<String, String> generateAESKeyIv() throws Exception {
        return cryptoService.generateAESKeyIv();
    }

    @PostMapping("/encrypt/aes")
    public String encryptAES(@RequestBody aesEncryptionReqDto data) throws Exception {
        return cryptoService.encryptAES(data.getData(), data.getKeyBase64(), data.getIvBase64());
    }

    @PostMapping("/decrypt/aes")
    public String decryptAES(@RequestBody aesEncryptionReqDto data) throws Exception {
        return cryptoService.decryptAES(data.getData(), data.getKeyBase64(), data.getIvBase64(), String.class);
    }

    @PostMapping("/encrypt/rsa")
    public String encryptRSA(@RequestBody String data) throws Exception {
        return cryptoService.encryptRSA(data);
    }

    @PostMapping("/decrypt/rsa")
    public String decryptRSA(@RequestBody String encryptedData) throws Exception {
        System.out.println(encryptedData);
        return cryptoService.decryptRSA(encryptedData, String.class);
    }

    @PostMapping("/encrypt/hybrid")
    public String hybridEncrypt(@RequestBody String data) throws Exception {
        return cryptoService.hybridEncrypt(data);
    }

    @PostMapping("/decrypt/hybrid")
    public String hybridDecrypt(@RequestBody String encryptedData) throws Exception {
        return cryptoService.hybridDecrypt(encryptedData, String.class);
    }
}
