package com.thornchg.rkt.shiro;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

import com.thornchg.rkt.entity.User;
import com.thornchg.rkt.service.UserService;
import com.thornchg.rkt.utils.JwtUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Resource;
import java.io.UnsupportedEncodingException;

public class JWTCredentialsMatcher implements CredentialsMatcher {

    private final Logger log = LoggerFactory.getLogger(JWTCredentialsMatcher.class);
    @Resource
    private UserService userService;

    /**
     * 身份匹配  验证token是否被篡改
     *
     * @param authenticationToken
     * @param authenticationInfo
     * @return
     */
    @Override
    public boolean doCredentialsMatch(AuthenticationToken authenticationToken, AuthenticationInfo authenticationInfo) {
        String token = (String) authenticationToken.getCredentials();
        /*Object stored = authenticationInfo.getCredentials();
        String salt = stored.toString();*/
        User user = (User) authenticationInfo.getPrincipals().getPrimaryPrincipal();

        if (!JwtUtils.isTokenExpired(token)) {
            JWTToken jwtToken = new JWTToken(token);
            String salt = userService.getTokenSalt(jwtToken.getUsername());
            if (salt != null) {
                try {
                    Algorithm algorithm = Algorithm.HMAC256(salt);
                    JWTVerifier verifier = JWT.require(algorithm)
                            .withClaim("username", user.getUsername())
                            .build();
                    verifier.verify(token);
                    return true;
                } catch (UnsupportedEncodingException | JWTVerificationException e) {
                    log.error("Token Error:{}", e.getMessage());
                }
            }
        }
        return false;
    }

}
