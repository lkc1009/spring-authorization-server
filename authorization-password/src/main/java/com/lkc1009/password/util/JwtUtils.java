package com.lkc1009.password.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Base64;
import java.util.Date;

public class JwtUtils {

    public static String base64EncodedSecretKey = Base64.getEncoder().encodeToString("jwt-secret".getBytes());

    public static String createJwt(String id, String sub, Date exp, SignatureAlgorithm alg, String secretKey){

        return Jwts.builder()
                .setId(id)
                .setSubject(sub)
                .setExpiration(exp)
                .signWith(alg, secretKey)
                .compact();
    }

    public static Claims parseJwtToken(String jwt, String secretKey){
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(jwt).getBody();
    }
}