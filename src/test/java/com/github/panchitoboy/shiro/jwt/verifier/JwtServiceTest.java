package com.github.panchitoboy.shiro.jwt.verifier;

import com.github.panchitoboy.shiro.jwt.JwtService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.codec.Hex;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

@RunWith(JUnit4.class)
public class JwtServiceTest {

    static String sharedKey;


    static JwtService jwtService = new JwtService();

    @BeforeClass
    public static void testing() throws IOException {
        SecureRandom random = new SecureRandom();
        byte[] byteKey = new byte[32];
        random.nextBytes(byteKey);
        sharedKey = Hex.encodeToString(byteKey);
        jwtService.setSecretKey(sharedKey);
        jwtService.setAlgorithm(JWSAlgorithm.HS256.getName());

    }

    @Test
    public void validToken() throws JOSEException, ParseException {
        JWTClaimsSet jwtClaims = getJWTClaimsSet("issuer", "subject", new Date(), new Date(), new Date(new Date().getTime() + 100000));

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        Payload payload = new Payload(jwtClaims.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        JWSSigner signer = new MACSigner(sharedKey);
        jwsObject.sign(signer);
        String token = jwsObject.serialize();

        SignedJWT signed = SignedJWT.parse(token);


        Assert.assertTrue("Must be valid", jwtService.validateToken(signed));
        Assert.assertTrue("Must be valid", jwtService.isNotExpired(signed));
    }

    @Test
    public void invalidTokenNotBeforeTime() throws JOSEException, ParseException {
        JWTClaimsSet jwtClaims = getJWTClaimsSet("issuer", "subject", new Date(), new Date(new Date().getTime() + 100000), new Date(new Date().getTime() + 200000));

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        Payload payload = new Payload(jwtClaims.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        JWSSigner signer = new MACSigner(sharedKey);
        jwsObject.sign(signer);
        String token = jwsObject.serialize();

        SignedJWT signed = SignedJWT.parse(token);


        Assert.assertTrue("Must be valid", jwtService.validateToken(signed));
        Assert.assertFalse("Must be invalid", jwtService.isNotExpired(signed));
    }

    @Test
    public void invalidTokenExpirationTime() throws JOSEException, ParseException {
        JWTClaimsSet jwtClaims = getJWTClaimsSet("issuer", "subject", new Date(), new Date(), new Date());

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

        Payload payload = new Payload(jwtClaims.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        JWSSigner signer = new MACSigner(sharedKey);
        jwsObject.sign(signer);
        String token = jwsObject.serialize();

        SignedJWT signed = SignedJWT.parse(token);

        Assert.assertTrue("Must be valid", jwtService.validateToken(signed));
        Assert.assertFalse("Must be invalid", jwtService.isNotExpired(signed));
    }

    private JWTClaimsSet getJWTClaimsSet(String issuer, String subject, Date issueTime, Date notBeforeTime, Date expirationTime) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.issuer(issuer);
        builder.subject(subject);
        builder.issueTime(issueTime);
        builder.notBeforeTime(notBeforeTime);
        builder.expirationTime(expirationTime);
        builder.jwtID(UUID.randomUUID().toString());
        return builder.build();
    }

}
