package com.github.panchitoboy.shiro.jwt;

import com.github.panchitoboy.shiro.jwt.repository.TokenResponse;
import com.github.panchitoboy.shiro.jwt.repository.UserDefault;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.ops4j.pax.shiro.cdi.ShiroIni;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Named;
import javax.inject.Singleton;
import java.text.ParseException;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

/**
 * Creates and verifies JWT tokens. For more details on JWT tokens and tutorial see
 * <a href="https://github.com/dwyl/learn-json-web-tokens">https://github.com/dwyl/learn-json-web-tokens</a>
 */
@ShiroIni
@Singleton
@Named("jwtService")
public class JwtService {

    Logger logger = LoggerFactory.getLogger(JwtService.class);


    private long expirationSeconds = 5;

    private String issuer = "none";

    private String secretKey = "72AC05536733581EA598CB31BA044D7D03A16B6057093DCF2B780A505607FF7"; // Needs to sufficiently long and random

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    private String algorithm = JWSAlgorithm.HS256.getName();

    public void setExpirationSeconds(long expirationSeconds) {
        this.expirationSeconds = expirationSeconds;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }


    public long getExpirationSeconds() {
        return expirationSeconds;
    }

    public String getIssuer()
    {
        return issuer;
    }

    public String getSecretKey()
    {
        return secretKey;
    }

    public TokenResponse createToken(UserDefault user) {
        return  new TokenResponse(user, createJWT(user.getPrincipal(), user.getHost(), user.getRoles()));

    }

    protected String createJWT(Object userId, String clientAddress, Set<String> roles) {

        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
            Date now = new Date();
            builder.issuer(getIssuer());
            builder.subject(userId.toString());
            builder.issueTime(now);
            builder.notBeforeTime(now);
            builder.expirationTime(new Date(now.getTime() + (getExpirationSeconds() * 1000)));
            builder.jwtID(UUID.randomUUID().toString());
            builder.claim("client IP", clientAddress);
            builder.claim("roles", roles.toArray());

            JWTClaimsSet claimsSet = builder.build();

            JWSHeader header = new JWSHeader(JWSAlgorithm.parse(algorithm));

            Payload payload = new Payload(claimsSet.toJSONObject());

            JWSObject jwsObject = new JWSObject(header, payload);

            JWSSigner signer = new MACSigner(getSecretKey());
            jwsObject.sign(signer);
            logger.info("Creating JWT session with expiration {} seconds", getExpirationSeconds());
            return jwsObject.serialize();
        } catch (JOSEException ex) {
            logger.error("Failed creating JWT token", ex);
            return null;
        }
    }

    public boolean validateToken(SignedJWT signed) {

        try {

            MACVerifier verifier = new MACVerifier(getSecretKey());
            return signed.verify(verifier);

        } catch (JOSEException ex) {
            logger.error("JOSEException validating signed JWT", ex);
            return false;
        }

    }
    public boolean isNotExpired(SignedJWT signed)
    {
        long time = System.currentTimeMillis();

        try {
            return signed.getJWTClaimsSet().getNotBeforeTime().getTime() <= time && time < signed.getJWTClaimsSet().getExpirationTime().getTime();
        } catch (ParseException e) {
            logger.error("ParseException parsing JWT for expired time", e);
            return false;
        }


    }


}
