package com.spring.crypto.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import javax.validation.constraints.NotNull;

@Component
@ConfigurationProperties(prefix = "rsa")
public class CryptoProperties {
    @NotNull
    private String privateKeyPath;
    @NotNull
    private String publicKeyPath;

    // Getters and Setters

    public String getPrivateKeyPath() {
        return privateKeyPath;
    }

    public void setPrivateKeyPath(String privateKeyPath) {
        this.privateKeyPath = privateKeyPath;
    }

    public String getPublicKeyPath() {
        return publicKeyPath;
    }

    public void setPublicKeyPath(String publicKeyPath) {
        this.publicKeyPath = publicKeyPath;
    }
}

/* spring-boot-configuration-processor dependency is required */
