package com.lkc1009.password.util;

import com.nimbusds.jose.util.Base64URL;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class PKCEUtils {

    public static String codeVerifierGenerator() {
        return Base64URL.encode(UUID.randomUUID().toString()).toString();
    }

    public static String codeChallengeGenerator(@NotNull String codeVerifier) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] digestCodeVerifier = messageDigest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64URL.encode(digestCodeVerifier).toString();
    }


    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 生成 code_verifier
        String codeVerifier = codeVerifierGenerator();
        // 生成 code_challenge
        String codeChallenge = codeChallengeGenerator(codeVerifier);

        System.out.println("code_verifier:" + codeVerifier);
        System.out.println("code_challenge:" + codeChallenge);
    }

}