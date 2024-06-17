package com.spring.crypto.dto;

public class aesEncryptionReqDto {
    String data;
    String keyBase64;
    String ivBase64;

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getKeyBase64() {
        return keyBase64;
    }

    public void setKeyBase64(String keyBase64) {
        this.keyBase64 = keyBase64;
    }

    public String getIvBase64() {
        return ivBase64;
    }

    public void setIvBase64(String ivBase64) {
        this.ivBase64 = ivBase64;
    }

    @Override
    public String toString() {
        return "aesEncryptionReqDto [data=" + data + ", keyBase64=" + keyBase64 + ", ivBase64="
                + ivBase64 + "]";
    }

};
