package com.github.panchitoboy.shiro.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.panchitoboy.shiro.jwt.JwtService;
import com.github.panchitoboy.shiro.jwt.example.boundary.UserRepositoryExample;
import com.github.panchitoboy.shiro.jwt.example.entity.UserDefaultExample;
import com.github.panchitoboy.shiro.jwt.example.jackson.MixInExample;
import com.github.panchitoboy.shiro.jwt.example.jackson.ObjectMapperProviderExample;
import com.github.panchitoboy.shiro.jwt.example.rest.JAXRSConfigurationExample;
import com.github.panchitoboy.shiro.jwt.example.rest.ResourceExample;
import com.github.panchitoboy.shiro.jwt.repository.TokenResponse;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.junit.InSequence;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.jboss.shrinkwrap.resolver.api.maven.ScopeType;
import org.jboss.shrinkwrap.resolver.api.maven.archive.importer.MavenImporter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.inject.Inject;
import javax.inject.Named;
import javax.json.JsonObject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.client.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.util.Date;

@RunWith(Arquillian.class)
@RunAsClient
public class JWTOrFormAuthenticationFilterTest {

    private static String token;
    private ObjectMapper objectMapper;

    @Inject
    @Named("jwtService")
    private JwtService jwtService;

    @Deployment
    public static Archive<?> deployment() {

        File[] filesCompile = Maven.resolver().loadPomFromFile("pom.xml").importDependencies(ScopeType.COMPILE).resolve().withTransitivity().asFile();
        File[] filestest = Maven.resolver().loadPomFromFile("pom.xml")
                .resolve("com.fasterxml.jackson.core:jackson-annotations", "com.fasterxml.jackson.core:jackson-databind", "com.fasterxml.jackson.core:jackson-core").withTransitivity().asFile();

        JavaArchive jar = ShrinkWrap.create(MavenImporter.class)
                .loadPomFromFile("pom.xml")
                .importBuildOutput()
                .as(JavaArchive.class);

        WebArchive war = ShrinkWrap.create(WebArchive.class)
                .addAsLibraries(filestest)
                .addAsLibraries(jar)
                .addAsLibraries(filesCompile)
                .addClasses(UserDefaultExample.class, UserRepositoryExample.class)
                .addClasses(JAXRSConfigurationExample.class, ObjectMapperProviderExample.class, ResourceExample.class)
                .addAsWebInfResource("WEB-INF/test.shiro.ini", "shiro.ini")
                .addAsWebInfResource("WEB-INF/web.xml", "web.xml")
                .addAsWebInfResource("META-INF/beans.xml", "beans.xml");

        System.out.println(war.toString(true));

        return war;
    }

    @ArquillianResource
    private URL base;

    private WebTarget target;

    @Before
    public void setUp() throws MalformedURLException {
        Client client = ClientBuilder.newBuilder().register(JacksonFeature.class).build();
        target = client.target(URI.create(new URL(base, "resources/test").toExternalForm()));

        objectMapper = new ObjectMapper();
        objectMapper.addMixIn(TokenResponse.class, MixInExample.class);
    }


    @Test(expected = NotAuthorizedException.class)
    @InSequence(1)
    public void securedWithoutToken() throws IOException {
        target.path("/secured").request().accept(MediaType.APPLICATION_JSON).get(TokenResponse.class);
    }


    @Test(expected = NotAuthorizedException.class)
    @InSequence(2)
    public void badLogin() throws IOException {
        UserDefaultExample user = new UserDefaultExample();
        user.setUserId("userId1");
        user.setPassword("password11");
        target.path("/login").request(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON).post(Entity.json(objectMapper.writeValueAsString(user)), TokenResponse.class);
    }


    @Test
    @InSequence(2)
    public void login() throws IOException {
        UserDefaultExample user = new UserDefaultExample();
        user.setUserId("userId1");
        user.setPassword("password1");
        Response r1 = target.path("/login").request(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON).post(Entity.json(objectMapper.writeValueAsString(user)));
        TokenResponse tokenResponse = objectMapper.readValue(r1.readEntity(String.class), TokenResponse.class);
        token = tokenResponse.getToken();
    }


    @Test
    @InSequence(3)
    public void secured() throws IOException {
        Invocation.Builder invocationBuilder = target.path("/secured").request().accept(MediaType.APPLICATION_JSON);
        invocationBuilder.header("Authorization", token);
        String r1 = invocationBuilder.get(String.class);
        Assert.assertEquals("Must have a message", "{\"message\":\"" + ResourceExample.MESSAGE + "\"}", r1);
    }



    @Test(expected = NotAuthorizedException.class)
    @InSequence(4)
    public void securedTokenExpired() throws IOException, ParseException, JOSEException {

        String expiredToken = generateNewJWT(token, new Date());
        Invocation.Builder invocationBuilder = target.path("/secured").request().accept(MediaType.APPLICATION_JSON);
        invocationBuilder.header("Authorization", expiredToken);
        invocationBuilder.get(JsonObject.class);
    }

    private String generateNewJWT(String token, Date expiration) throws ParseException, JOSEException {

        SignedJWT currentJwsObject = SignedJWT.parse(token);

        // Create a claimsset with the new expiration time
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder(currentJwsObject.getJWTClaimsSet());
        claimsBuilder.expirationTime(expiration);
        claimsBuilder.notBeforeTime(expiration);
        claimsBuilder.issueTime(expiration);
        // Create a new JWT token based on the old one
        SignedJWT expiredJwsObject = new SignedJWT(currentJwsObject.getHeader(), claimsBuilder.build());

        // Sign it with the key so it is valid
        JWSSigner signer = new MACSigner("72AC05536733581EA598CB31BA044D7D03A16B6057093DCF2B780A505607FF7");
        expiredJwsObject.sign(signer);
        return expiredJwsObject.serialize();
    }

    @Test
    @InSequence(5)
    public void login2() throws IOException {
        UserDefaultExample user = new UserDefaultExample();
        user.setUserId("userId2");
        user.setPassword("password2");
        Response r1 = target.path("/login").request(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON).post(Entity.json(objectMapper.writeValueAsString(user)));
        TokenResponse tokenResponse = objectMapper.readValue(r1.readEntity(String.class), TokenResponse.class);
        token = tokenResponse.getToken();
    }
    @Test(expected = NotAuthorizedException.class)
    @InSequence(6)
    public void secured2withoutRole() throws IOException {
        Invocation.Builder invocationBuilder = target.path("/secured").request().accept(MediaType.APPLICATION_JSON);
        invocationBuilder.header("Authorization", token);
        String r1 = invocationBuilder.get(String.class);
        Assert.assertEquals("Must have a message", "{\"message\":\"" + ResourceExample.MESSAGE + "\"}", r1);
    }


}
