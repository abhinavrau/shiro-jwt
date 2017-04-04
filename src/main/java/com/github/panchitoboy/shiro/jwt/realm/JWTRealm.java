package com.github.panchitoboy.shiro.jwt.realm;

import com.github.panchitoboy.shiro.jwt.JwtService;
import com.github.panchitoboy.shiro.jwt.filter.JWTAuthenticationToken;
import com.github.panchitoboy.shiro.jwt.repository.UserRepository;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.ops4j.pax.shiro.cdi.ShiroIni;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import java.text.ParseException;
import java.util.Arrays;

@ShiroIni
public class JWTRealm extends AuthorizingRealm {

    Logger logger = LoggerFactory.getLogger(JWTRealm.class);

    @Inject
    private UserRepository userRepository;

    @Named("jwtService")
    @Inject
    private JwtService jwtService;



    @Override
    public boolean supports(AuthenticationToken token) {
        return token != null && token instanceof JWTAuthenticationToken;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        JWTAuthenticationToken upToken = (JWTAuthenticationToken) token;

        if (jwtService.validateToken(upToken.getToken())) {

            if(false == jwtService.isNotExpired(upToken.getToken()))
            {
                logger.info("Token expired for user: {}", upToken.getPrincipal());
                throw new ExpiredCredentialsException("Token expired for user: ".concat((String)upToken.getPrincipal()));
            }

            SimpleAccount account = new SimpleAccount(upToken.getPrincipal(), upToken.getToken(), getName());
            String[] roles = new String[0];
            try {
                roles = upToken.getToken().getJWTClaimsSet().getStringArrayClaim("roles");
            } catch (ParseException e) {

                logger.error("ParseException {} parsing roles from JWT of user {}. No roles will be asserted ", e.getMessage(), upToken.getPrincipal());
                logger.debug("ParseException stack trace:", e);
            }
            account.addRole(Arrays.asList(roles));
            return account;
        }

        return null;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        SimpleAccount info = null;

        if(isAuthenticationCachingEnabled())
        {
            Object key = getAuthenticationCacheKey(principals);

            if(key!=null)
            {
                info =  (SimpleAccount) getAuthenticationCache().get(key);
            }
            else {
                logger.error("Account not found in Authentication cache");
            }
        }
        else
        {
            logger.error("Authentication Cache not enabled. This needs to be enabled!");
        }

        return info;
    }




}
