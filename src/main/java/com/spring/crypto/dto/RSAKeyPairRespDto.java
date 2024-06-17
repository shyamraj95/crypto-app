package com.spring.crypto.dto;

import lombok.Data;

@Data
public class RSAKeyPairRespDto {
    private String publicKey;
    private String privateKey;
    private String publicKeyDownloadUrl;
    private String privateKeyDownloadUrl;
};